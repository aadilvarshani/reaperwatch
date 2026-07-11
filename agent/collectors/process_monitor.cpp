#include "process_monitor.h"

#include <windows.h>
#include <winternl.h>  // NtQueryInformationProcess, PEB, RTL_USER_PROCESS_PARAMETERS
#include <tlhelp32.h>  // CreateToolhelp32Snapshot, PROCESSENTRY32W
#include <sddl.h>      // ConvertSidToStringSidW
#include <bcrypt.h>    // CNG hashing: BCryptOpenAlgorithmProvider, BCryptHashData, ...
#include <wincrypt.h>  // CryptQueryObject, CryptMsgGetParam, CertGetNameString
#include <wintrust.h>  // WinVerifyTrust, WINTRUST_DATA
#include <softpub.h>   // WINTRUST_ACTION_GENERIC_VERIFY_V2
#include <mscat.h>     // CryptCATAdmin* system-catalog verification

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <vector>

#include "process_event.h"
#include "win_utils.h"

namespace reaperwatch {

// collect_process_events() lives in etw_consumer.cpp (the live ETW acquisition).

// Resolve a PID to its full image path on disk. See header for contract.
std::optional<std::string> get_process_path(std::uint32_t pid) {
    // Open with the least access we need; UniqueHandle closes it automatically.
    UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.valid()) {
        // Process may have exited, or we lack rights; GetLastError() has details.
        return std::nullopt;
    }

    // QueryFullProcessImageNameW fills a wide buffer; `size` is in/out (capacity
    // in chars, then length written out). Windows paths can be long, so start big.
    DWORD size = 32768;
    std::wstring buffer(size, L'\0');
    if (!QueryFullProcessImageNameW(process.get(), 0, buffer.data(), &size)) {
        return std::nullopt;
    }

    buffer.resize(size);    // shrink to the actual length written
    return narrow(buffer);  // UTF-16 -> UTF-8 for our data model
}

// Recover a process's full command line by walking its PEB. See header contract.
// The walk is three ReadProcessMemory "hops": PEB -> parameters -> the text.
std::optional<std::string> get_process_command_line(std::uint32_t pid) {
    // We must READ the target's memory now, so we add PROCESS_VM_READ to the
    // access rights we used in T2.
    UniqueHandle process(OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!process.valid()) {
        return std::nullopt;
    }

    // Ask the native API where this process's PEB lives.
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returned = 0;
    const NTSTATUS status = NtQueryInformationProcess(
        process.get(), ProcessBasicInformation, &pbi, sizeof(pbi), &returned);
    if (status < 0 || pbi.PebBaseAddress == nullptr) {  // NTSTATUS < 0 == failure
        return std::nullopt;
    }

    // HOP 1: copy the PEB out of the target's address space.
    PEB peb{};
    if (!ReadProcessMemory(process.get(), pbi.PebBaseAddress,
                           &peb, sizeof(peb), nullptr)) {
        return std::nullopt;
    }

    // HOP 2: follow peb.ProcessParameters (a target address) into `params`.
    RTL_USER_PROCESS_PARAMETERS params{};
    if (!ReadProcessMemory(process.get(), peb.ProcessParameters,
                           &params, sizeof(params), nullptr)) {
        return std::nullopt;
    }

    // HOP 3: copy the command-line text. UNICODE_STRING.Length is in BYTES, and
    // the text is not null-terminated, so divide by sizeof(wchar_t) for the count.
    if (params.CommandLine.Length == 0 || params.CommandLine.Buffer == nullptr) {
        return std::nullopt;
    }
    std::wstring cmdline(params.CommandLine.Length / sizeof(wchar_t), L'\0');
    if (!ReadProcessMemory(process.get(), params.CommandLine.Buffer,
                           cmdline.data(), params.CommandLine.Length, nullptr)) {
        return std::nullopt;
    }
    return narrow(cmdline);  // UTF-16 -> UTF-8 for our data model
}

// File-local helpers for lineage. An unnamed ("anonymous") namespace gives them
// internal linkage: they exist only in this .cpp and can't collide with names
// elsewhere in the program. Use it for implementation details you don't export.
namespace {

// One row of a process snapshot: the parent's PID and the image (file) name.
struct ProcEntry {
    std::uint32_t ppid = 0;
    std::wstring  name;
};

// Point-in-time snapshot of all processes -> map of pid -> {ppid, name}, via the
// Toolhelp API. Returns an empty map on failure.
std::unordered_map<std::uint32_t, ProcEntry> snapshot_processes() {
    std::unordered_map<std::uint32_t, ProcEntry> processes;

    UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap.valid()) {
        return processes;  // empty
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);  // REQUIRED before the first call, or it fails
    if (Process32FirstW(snap.get(), &entry)) {
        do {
            processes[entry.th32ProcessID] =
                ProcEntry{entry.th32ParentProcessID, entry.szExeFile};
        } while (Process32NextW(snap.get(), &entry));
    }
    return processes;
}

// The moment a process was created, as a 64-bit timestamp (100ns ticks). Used to
// detect PID reuse: a genuine parent must be OLDER than its child. nullopt on failure.
std::optional<std::uint64_t> get_process_creation_time(std::uint32_t pid) {
    UniqueHandle p(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!p.valid()) {
        return std::nullopt;
    }
    FILETIME creation{}, exit_t{}, kernel_t{}, user_t{};
    if (!GetProcessTimes(p.get(), &creation, &exit_t, &kernel_t, &user_t)) {
        return std::nullopt;
    }
    ULARGE_INTEGER t{};
    t.LowPart  = creation.dwLowDateTime;
    t.HighPart = creation.dwHighDateTime;
    return t.QuadPart;
}

}  // namespace

// Populate parent/grandparent lineage for `pid`, guarding against PID reuse.
void get_process_lineage(std::uint32_t pid, ParentInfo& parent,
                         GrandparentInfo& grandparent) {
    const auto processes = snapshot_processes();

    const auto child_it = processes.find(pid);
    if (child_it == processes.end()) {
        return;  // subject not in the snapshot (it may have just exited)
    }
    const std::uint32_t parent_pid = child_it->second.ppid;

    const auto parent_it = processes.find(parent_pid);
    if (parent_it == processes.end()) {
        return;  // the parent has already exited; nothing to record
    }

    // PID-reuse guard: a real parent must be no younger than its child. If the
    // PID was recycled, the process now holding it started later -> reject it.
    const auto child_time = get_process_creation_time(pid);
    const auto parent_time = get_process_creation_time(parent_pid);
    if (!child_time.has_value() || !parent_time.has_value()) {
        return;  // can't verify -> don't record an unverified parent
    }
    if (*parent_time > *child_time) {
        return;  // parent started after the child: PID reused, impostor
    }

    parent.pid  = parent_pid;
    parent.name = narrow(parent_it->second.name);

    // Grandparent: one lookup level up, from the parent's ppid.
    const std::uint32_t grandparent_pid = parent_it->second.ppid;
    const auto grandparent_it = processes.find(grandparent_pid);
    if (grandparent_it != processes.end()) {
        grandparent.pid  = grandparent_pid;
        grandparent.name = narrow(grandparent_it->second.name);
    }
}

// Populate the user/security context (name, domain, sid, is_admin, is_system).
void get_process_user(std::uint32_t pid, UserContext& user) {
    UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.valid()) {
        return;
    }

    // Open the process's access token for reading. OpenProcessToken hands back a
    // raw HANDLE we must close, so wrap it in UniqueHandle like any other handle.
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(process.get(), TOKEN_QUERY, &raw_token)) {
        return;
    }
    UniqueHandle token(raw_token);

    // Get the user SID via the two-call pattern (call 1 sizes, call 2 fills).
    DWORD needed = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &needed);
    std::vector<BYTE> buffer(needed);
    if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), needed, &needed)) {
        return;
    }
    // The buffer's bytes ARE a TOKEN_USER; view them as one. The SID lives inside.
    const TOKEN_USER* token_user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    PSID sid = token_user->User.Sid;

    // SID -> string form (e.g. "S-1-5-18"). ConvertSidToStringSidW allocates the
    // string, so we LocalFree it immediately after copying it out.
    LPWSTR sid_str = nullptr;
    if (ConvertSidToStringSidW(sid, &sid_str)) {
        user.sid = narrow(sid_str);
        LocalFree(sid_str);
    }

    // Resolve the SID to a friendly account name + domain (two-call pattern again).
    DWORD name_len = 0, domain_len = 0;
    SID_NAME_USE use{};
    LookupAccountSidW(nullptr, sid, nullptr, &name_len, nullptr, &domain_len, &use);
    std::wstring name(name_len, L'\0');
    std::wstring domain(domain_len, L'\0');
    if (LookupAccountSidW(nullptr, sid, name.data(), &name_len,
                          domain.data(), &domain_len, &use)) {
        name.resize(name_len);      // LookupAccountSid returns the length w/o the null
        domain.resize(domain_len);
        user.name = narrow(name);
        user.domain = narrow(domain);
    }

    // Power flags: SYSTEM (well-known SID) and elevated/admin (token elevation).
    user.is_system = (IsWellKnownSid(sid, WinLocalSystemSid) != 0);

    TOKEN_ELEVATION elevation{};
    DWORD elev_size = sizeof(elevation);
    if (GetTokenInformation(token.get(), TokenElevation,
                            &elevation, sizeof(elevation), &elev_size)) {
        user.is_admin = (elevation.TokenIsElevated != 0);
    }
}

// File-local hashing helpers.
namespace {

// Turn raw digest bytes into a lowercase hex string (e.g. {0xAB,0x01} -> "ab01").
std::string to_hex(const std::vector<BYTE>& bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (BYTE b : bytes) {
        out.push_back(digits[b >> 4]);     // high nibble
        out.push_back(digits[b & 0x0F]);   // low nibble
    }
    return out;
}

// Hash a file with the given CNG algorithm id (e.g. BCRYPT_SHA256_ALGORITHM),
// streaming it in 64 KB chunks. Returns lowercase hex, or nullopt on failure.
std::optional<std::string> hash_file(const std::wstring& path, LPCWSTR alg_id) {
    // Open the file first: if we can't read it, there's nothing to hash.
    std::ifstream file(std::filesystem::path(path), std::ios::binary);
    if (!file) {
        return std::nullopt;
    }

    // Open a CNG algorithm provider for this hash algorithm.
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, alg_id, nullptr, 0) < 0) {
        return std::nullopt;
    }

    // Create a hash object from it.
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }

    // ── GAP: stream the file through the hash in 64 KB chunks ───────────────
    // We loop, reading the file one chunk at a time, and feed each chunk to the
    // hash object (this is why a huge executable never blows up our memory).
    std::vector<char> chunk(64 * 1024);
    while (file) {
        file.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const std::streamsize got = file.gcount();  // bytes actually read this pass
        if (got > 0) {
            BCryptHashData(hash, reinterpret_cast<PUCHAR>(chunk.data()),
                           static_cast<ULONG>(got), 0);
        }
    }
    // ─────────────────────────────────────────────────────────────────────────

    // Finalize: ask the algorithm how long its digest is, then pull it out.
    DWORD hash_len = 0, cb = 0;
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                      reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cb, 0);
    std::vector<BYTE> digest(hash_len);
    const NTSTATUS fin = BCryptFinishHash(hash, digest.data(), hash_len, 0);

    // Release the CNG objects on every path from here.
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    if (fin < 0) {
        return std::nullopt;
    }
    return to_hex(digest);
}

}  // namespace

std::optional<std::string> get_file_sha256(const std::string& path) {
    return hash_file(widen(path), BCRYPT_SHA256_ALGORITHM);
}

std::optional<std::string> get_file_md5(const std::string& path) {
    return hash_file(widen(path), BCRYPT_MD5_ALGORITHM);
}

// File-local signature helpers.
namespace {

// Extract the signer's display name from a file's EMBEDDED Authenticode signature.
// Returns nullopt when the file has no embedded signature (e.g. catalog-signed OS
// binaries) -- extracting the catalog signer is a later refinement.
std::optional<std::string> get_signer_name(const std::wstring& path) {
    HCERTSTORE store = nullptr;
    HCRYPTMSG  msg = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr,
                          nullptr, &store, &msg, nullptr)) {
        return std::nullopt;  // no embedded signature
    }

    std::optional<std::string> result;

    // Pull the signer info out of the PKCS#7 message (two-call pattern).
    DWORD signer_size = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_size)) {
        std::vector<BYTE> signer_buf(signer_size);
        if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0,
                             signer_buf.data(), &signer_size)) {
            const auto* signer_info =
                reinterpret_cast<const CMSG_SIGNER_INFO*>(signer_buf.data());

            // Locate the signer's certificate in the store by issuer + serial.
            CERT_INFO cert_id{};
            cert_id.Issuer = signer_info->Issuer;
            cert_id.SerialNumber = signer_info->SerialNumber;
            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, &cert_id, nullptr);
            if (cert) {
                // Read the certificate subject's friendly display name.
                const DWORD len = CertGetNameStringW(
                    cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
                if (len > 1) {  // len includes the null terminator
                    std::wstring name(len, L'\0');
                    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                       nullptr, name.data(), len);
                    name.resize(len - 1);
                    result = narrow(name);
                }
                CertFreeCertificateContext(cert);
            }
        }
    }

    if (msg) CryptMsgClose(msg);
    if (store) CertCloseStore(store, 0);
    return result;
}

// Fallback for OS binaries with no embedded signature: check whether a system
// security catalog vouches for the file's hash, verify against it, and read the
// catalog's own signer. Returns true when the file is validly catalog-signed.
bool verify_via_catalog(const std::wstring& path, std::optional<std::string>& signer) {
    UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                  nullptr, OPEN_EXISTING, 0, nullptr));
    if (!file.valid()) {
        return false;
    }

    // Acquire a catalog context that hashes with SHA256 (matches modern catalogs).
    HCATADMIN admin = nullptr;
    if (!CryptCATAdminAcquireContext2(&admin, nullptr, BCRYPT_SHA256_ALGORITHM,
                                      nullptr, 0)) {
        return false;
    }

    // Compute this file's catalog hash (two-call pattern).
    DWORD hash_len = 0;
    CryptCATAdminCalcHashFromFileHandle2(admin, file.get(), &hash_len, nullptr, 0);
    std::vector<BYTE> hash(hash_len);
    if (hash_len == 0 ||
        !CryptCATAdminCalcHashFromFileHandle2(admin, file.get(), &hash_len,
                                              hash.data(), 0)) {
        CryptCATAdminReleaseContext(admin, 0);
        return false;
    }

    // Find a catalog that lists this file's hash (nullptr => none vouches for it).
    HCATINFO cat =
        CryptCATAdminEnumCatalogFromHash(admin, hash.data(), hash_len, 0, nullptr);

    bool signed_ok = false;
    if (cat) {
        // The catalog "member tag" is the file hash as an uppercase hex string.
        static const wchar_t hexd[] = L"0123456789ABCDEF";
        std::wstring member_tag;
        member_tag.reserve(hash.size() * 2);
        for (BYTE b : hash) {
            member_tag.push_back(hexd[b >> 4]);
            member_tag.push_back(hexd[b & 0x0F]);
        }

        CATALOG_INFO ci{};
        ci.cbStruct = sizeof(ci);
        if (CryptCATCatalogInfoFromContext(cat, &ci, 0)) {
            // Re-verify the file against the specific catalog we found.
            WINTRUST_CATALOG_INFO wci{};
            wci.cbStruct = sizeof(wci);
            wci.pcwszCatalogFilePath = ci.wszCatalogFile;
            wci.pcwszMemberFilePath = path.c_str();
            wci.pcwszMemberTag = member_tag.c_str();
            wci.hMemberFile = file.get();
            wci.pbCalculatedFileHash = hash.data();
            wci.cbCalculatedFileHash = hash_len;
            wci.hCatAdmin = admin;

            WINTRUST_DATA wd{};
            wd.cbStruct = sizeof(wd);
            wd.dwUIChoice = WTD_UI_NONE;
            wd.fdwRevocationChecks = WTD_REVOKE_NONE;
            wd.dwUnionChoice = WTD_CHOICE_CATALOG;
            wd.pCatalog = &wci;
            wd.dwStateAction = WTD_STATEACTION_VERIFY;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            signed_ok = (WinVerifyTrust(nullptr, &action, &wd) == ERROR_SUCCESS);
            wd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &action, &wd);

            // The catalog file itself is embedded-signed (by Microsoft), so reuse
            // our embedded extractor on it to name the signer.
            if (signed_ok) {
                signer = get_signer_name(ci.wszCatalogFile);
            }
        }
        CryptCATAdminReleaseCatalogContext(admin, cat, 0);
    }

    CryptCATAdminReleaseContext(admin, 0);
    return signed_ok;
}

}  // namespace

// Verify a file's Authenticode signature and, if signed, name the signer.
FileSignature get_file_signature(const std::string& path) {
    FileSignature result;
    const std::wstring wpath = widen(path);

    // Describe the file we want WinVerifyTrust to check.
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wpath.c_str();

    // Configure the trust check: no UI, file-based, verify action.
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;               // never pop a dialog
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;  // skip online revocation for now
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &file_info;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // First try the file's EMBEDDED signature. Verify (VERIFY allocates internal
    // state), record the result, then CLOSE to free that state. ERROR_SUCCESS
    // means validly signed.
    const LONG status = WinVerifyTrust(nullptr, &action, &wd);
    result.is_signed = (status == ERROR_SUCCESS);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);

    if (result.is_signed) {
        // Embedded signature: read the signer straight from the file.
        result.signer = get_signer_name(wpath);
    } else {
        // No embedded signature: fall back to the system catalogs (this is how
        // most OS binaries, e.g. notepad.exe, are signed).
        result.is_signed = verify_via_catalog(wpath, result.signer);
    }
    return result;
}

// Collect this machine's host context. See header for the caching note.
HostContext get_host_context() {
    HostContext host;

    // ── GAP 1: hostname (two-call pattern) ──────────────────────────────────
    // GetComputerNameExW(ComputerNamePhysicalDnsHostname, ...):
    //   DWORD size = 0;
    //   GetComputerNameExW(ComputerNamePhysicalDnsHostname, nullptr, &size);
    //   std::wstring name(size, L'\0');
    //   if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, name.data(), &size)) {
    //       name.resize(size);                 // size now excludes the null
    //       host.hostname = narrow(name);
    //   }
    // TODO(gap1): fill in the hostname lookup.
    // ────────────────────────────────────────────────────────────────────────
    DWORD size = 0;
    GetComputerNameExW(ComputerNamePhysicalDnsHostname, nullptr, &size);
    std::wstring name(size, L'\0');
    if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, name.data(), &size)) {
        name.resize(size);
        host.hostname = narrow(name);
    }

    // OS version: GetVersionEx lies (caps at 6.2 without a manifest), so we call
    // the real RtlGetVersion from ntdll, loaded dynamically.
    OSVERSIONINFOW osv{};
    osv.dwOSVersionInfoSize = sizeof(osv);
    const auto rtl_get_version = reinterpret_cast<LONG(WINAPI*)(OSVERSIONINFOW*)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    if (rtl_get_version && rtl_get_version(&osv) == 0) {  // 0 == STATUS_SUCCESS
        std::string name = "Windows";
        if (osv.dwMajorVersion == 10 && osv.dwBuildNumber >= 22000) {
            name += " 11";  // Win 10 and 11 both report major==10; build splits them
        } else if (osv.dwMajorVersion == 10) {
            name += " 10";
        }
        host.os = name + " (build " + std::to_string(osv.dwBuildNumber) + ")";
    }
SYSTEM_INFO si{};
GetNativeSystemInfo(&si);
switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: host.arch = "x64";     break;
    case PROCESSOR_ARCHITECTURE_ARM64: host.arch = "arm64";   break;
    case PROCESSOR_ARCHITECTURE_INTEL: host.arch = "x86";     break;
    default:                           host.arch = "unknown"; break;
}


    return host;
}

// File-local helpers for the event envelope.
namespace {

// ISO8601 UTC timestamp with milliseconds, e.g. "2026-07-11T13:45:07.123Z".
std::string current_timestamp() {
    SYSTEMTIME st{};
    GetSystemTime(&st);  // UTC
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                  st.wSecond, st.wMilliseconds);
    return buf;
}

// Monotonic, thread-safe event counter. std::atomic makes concurrent collectors
// safe without a lock; relaxed ordering is fine for a standalone counter.
std::uint64_t next_sequence_id() {
    static std::atomic<std::uint64_t> counter{0};
    return counter.fetch_add(1, std::memory_order_relaxed);
}

// Basename of a UTF-8 path (last component). We split on the ASCII slash bytes
// directly, which is UTF-8-safe; std::filesystem::path::string() would re-encode
// through the ANSI code page and mangle non-ASCII names.
std::string basename_of(const std::string& path) {
    const size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

}  // namespace

// Assemble a fully-enriched process_create event. See header for the contract.
ProcessEvent build_process_event(std::uint32_t pid) {
    ProcessEvent event;

    // Envelope.
    event.event_type  = "process_create";
    event.timestamp   = current_timestamp();
    event.sequence_id = next_sequence_id();

    // Subject process: identity, then file-based enrichment keyed off the path.
    event.process.pid     = pid;
    event.process.path    = get_process_path(pid);
    event.process.cmdline = get_process_command_line(pid);
    if (event.process.path) {
        event.process.name   = basename_of(*event.process.path);
        event.process.sha256 = get_file_sha256(*event.process.path);
        event.process.md5    = get_file_md5(*event.process.path);
        const FileSignature sig = get_file_signature(*event.process.path);
        event.process.is_signed = sig.is_signed;
        event.process.signer    = sig.signer;
    }

    // Lineage, identity, host.
    get_process_lineage(pid, event.parent, event.grandparent);
    get_process_user(pid, event.user);
    event.host = get_host_context();

    // Behavioural flags: is_lolbin / unusual_parent are simple heuristics added in
    // a later step; is_hollow / is_injected need memory analysis (a later concept).
    return event;
}

}  // namespace reaperwatch
