#pragma once

// process_event.h
//
// In-memory data model for a single normalized process-creation event.
//
// This header defines only the shape of the data; it is independent of how
// events are collected (ETW, kernel driver) or serialized (JSON), so those
// layers can change without touching the model.
//
// Encoding: every string here is UTF-8. Win32 APIs return UTF-16; we convert at
// the boundary and store UTF-8 throughout.

#include <cstdint>
#include <optional>
#include <string>

namespace reaperwatch {

// The machine this agent runs on.
struct HostContext {
    std::string hostname;  // e.g. "WIN11-VICTIM"
    std::string os;        // e.g. "Windows 11 Pro 22H2 (build 22621)"
    std::string arch;      // e.g. "x64"
};

// The subject process the event is about.
// Fields that can legitimately be absent (a query fails, an unsigned file has no
// signer) are std::optional; fields we always have (pid, name) are plain.
struct ProcessInfo {
    std::uint32_t pid = 0;                // process id (DWORD)
    std::string   name;                   // image file name, e.g. "cmd.exe"
    std::optional<std::string> path;      // full path, e.g. "C:\\Windows\\System32\\cmd.exe"
    std::optional<std::string> cmdline;   // full command line
    std::optional<std::string> sha256;    // hex, lowercase
    std::optional<std::string> md5;       // hex, lowercase
    bool is_signed = false;               // is_signed because `signed` is a C++ keyword; JSON key is "signed"
    std::optional<std::string> signer;    // present only when is_signed
};

// The process that created the subject process.
struct ParentInfo {
    std::uint32_t pid = 0;
    std::string   name;                   // e.g. "explorer.exe"
    std::optional<std::string> path;
    std::optional<std::string> cmdline;
    std::optional<std::string> sha256;
};

// The parent's parent -- enough to trace lineage one more level.
struct GrandparentInfo {
    std::uint32_t pid = 0;
    std::string   name;                   // e.g. "wininit.exe"
};

// The user / security context the process runs under.
struct UserContext {
    std::string name;                     // resolved account name, e.g. "victim"
    std::string domain;                   // e.g. "WIN11-VICTIM"
    std::string sid;                      // e.g. "S-1-5-21-...-1013"
    bool is_admin = false;                // user is a local administrator
    bool is_system = false;               // runs as NT AUTHORITY\SYSTEM
};

// Behavioural / threat flags. is_hollow and is_injected require memory analysis
// added in a later concept; they stay false for now.
struct Flags {
    bool is_lolbin = false;               // trusted-but-abusable built-in (powershell, rundll32, ...)
    bool unusual_parent = false;          // abnormal parent->child pair (e.g. winword.exe -> cmd.exe)
    bool is_hollow = false;
    bool is_injected = false;
};

// A complete, normalized process-creation event: envelope + composed payload.
struct ProcessEvent {
    std::string   event_type;             // always "process_create"
    std::string   timestamp;              // ISO8601 with milliseconds
    std::uint64_t sequence_id = 0;        // monotonically increasing (64-bit: never wraps)

    ProcessInfo     process;
    ParentInfo      parent;
    GrandparentInfo grandparent;
    UserContext     user;
    HostContext     host;
    Flags           flags;
};

}  // namespace reaperwatch
