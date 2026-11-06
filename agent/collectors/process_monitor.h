#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "process_event.h"
#include "win_utils.h"

namespace reaperwatch {

void collect_process_events();

// Given an already-open handle to a process, return its full image path on
// disk as UTF-8 (e.g. "C:\\Windows\\System32\\notepad.exe"). Returns
// std::nullopt if the handle is invalid or the query fails.
std::optional<std::string> get_process_path(const UniqueHandle& process);

// Given an already-open handle to a process (opened with PROCESS_VM_READ),
// return the full command line it was launched with, as UTF-8, by reading the
// target's PEB. Returns std::nullopt on any failure (invalid handle, or a
// memory read fails). NOTE: 64-bit targets only for now; reading a 32-bit
// (WOW64) process's command line is a later addition.
//
// Not the primary command-line source for build_process_event anymore (RW-2:
// the ETW payload's CommandLine wins that race). Kept for the argument-spoofing
// test later in this epic, which needs this delayed, independent PEB read to
// compare against the payload's value.
std::optional<std::string> get_process_command_line(const UniqueHandle& process);

// Populate `parent` (pid + name) and `grandparent` (pid + name) for `pid`,
// using a process snapshot and guarding against PID reuse via creation-time
// validation. `process` is the subject's already-open handle, reused for the
// subject's own creation-time check (the parent is a different process, so
// its creation time still requires its own handle). Fields that can't be
// resolved keep their defaults.
void get_process_lineage(std::uint32_t pid, const UniqueHandle& process,
                         ParentInfo& parent, GrandparentInfo& grandparent);

// Populate `user` (name, domain, sid, is_admin, is_system) from the given
// already-open process handle's access token. Fields that can't be resolved
// keep their defaults (e.g. if the token can't be opened because the target
// is higher-privileged).
void get_process_user(const UniqueHandle& process, UserContext& user);

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

// Return this machine's host context (hostname, OS, architecture). Values are
// constant for the machine's lifetime, so callers may compute this once and cache
// it rather than per event.
HostContext get_host_context();

// Assemble a fully-enriched process_create event from facts already decoded
// from the ETW payload/header (pid, parent pid, session, SID, image name,
// command line -- see RawProcessFacts). Only what the payload can't carry
// (full path, hashes, signature, lineage names/grandparent, token details)
// still comes from a live query, off one handle opened as early as possible.
// Also stamps the envelope (event_type, timestamp, sequence_id).
ProcessEvent build_process_event(const RawProcessFacts& facts);

}  // namespace reaperwatch
