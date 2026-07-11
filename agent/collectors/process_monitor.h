#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "process_event.h"

namespace reaperwatch {

void collect_process_events();

// Given a process id, return that process's full image path on disk as UTF-8
// (e.g. "C:\\Windows\\System32\\notepad.exe"). Returns std::nullopt if the
// process can't be opened or queried (it may have exited, or access denied).
std::optional<std::string> get_process_path(std::uint32_t pid);

// Given a process id, return the full command line it was launched with, as
// UTF-8, by reading the target's PEB. Returns std::nullopt on any failure
// (exited, access denied, or a memory read fails). NOTE: 64-bit targets only for
// now; reading a 32-bit (WOW64) process's command line is a later addition.
std::optional<std::string> get_process_command_line(std::uint32_t pid);

// Populate `parent` (pid + name) and `grandparent` (pid + name) for the given
// process, using a process snapshot and guarding against PID reuse via
// creation-time validation. Fields that can't be resolved keep their defaults.
void get_process_lineage(std::uint32_t pid, ParentInfo& parent,
                         GrandparentInfo& grandparent);

// Populate `user` (name, domain, sid, is_admin, is_system) for the given process
// by reading its access token. Fields that can't be resolved keep their defaults
// (e.g. if the token can't be opened because the target is higher-privileged).
void get_process_user(std::uint32_t pid, UserContext& user);

// Compute the SHA256 / MD5 of a file (given its UTF-8 path), returned as a
// lowercase hex string. std::nullopt if the file can't be read or hashed. The
// file is streamed in chunks, so memory use is constant regardless of size.
std::optional<std::string> get_file_sha256(const std::string& path);
std::optional<std::string> get_file_md5(const std::string& path);

// Result of an Authenticode signature check on a file.
struct FileSignature {
    bool is_signed = false;             // valid signature (embedded OR system catalog)
    std::optional<std::string> signer;  // signer display name (embedded sigs for now)
};

// Verify a file's Authenticode signature and, when signed, extract the signer's
// display name. Handles both EMBEDDED signatures and system-catalog signatures
// (OS binaries with no embedded signature). Unsigned/unknown files come back
// with is_signed == false.
FileSignature get_file_signature(const std::string& path);

}  // namespace reaperwatch
