#include <windows.h>

#include <iostream>

#include "collectors/process_monitor.h"

int main() {
    // Temporary T2 self-test: resolve OUR OWN process id to a path and print it.
    // GetCurrentProcessId() returns the PID of the running agent itself, so we
    // have a known process to test enrichment against without any event feed.
    const std::uint32_t my_pid = GetCurrentProcessId();

    std::optional<std::string> path = reaperwatch::get_process_path(my_pid);
    if (path.has_value()) {
        std::cout << "PID " << my_pid << " path: " << *path << "\n";
    } else {
        std::cout << "PID " << my_pid << " path: <failed to resolve>\n";
    }

    std::optional<std::string> cmd = reaperwatch::get_process_command_line(my_pid);
    if (cmd.has_value()) {
        std::cout << "PID " << my_pid << " cmdline: " << *cmd << "\n";
    } else {
        std::cout << "PID " << my_pid << " cmdline: <failed to resolve>\n";
    }

    reaperwatch::ParentInfo parent;
    reaperwatch::GrandparentInfo grandparent;
    reaperwatch::get_process_lineage(my_pid, parent, grandparent);
    std::cout << "parent:      pid " << parent.pid << " name " << parent.name << "\n";
    std::cout << "grandparent: pid " << grandparent.pid << " name " << grandparent.name << "\n";

    reaperwatch::UserContext user;
    reaperwatch::get_process_user(my_pid, user);
    std::cout << "user:        " << user.domain << "\\" << user.name
              << "  sid=" << user.sid
              << "  admin=" << user.is_admin
              << "  system=" << user.is_system << "\n";

    if (path.has_value()) {
        std::optional<std::string> sha = reaperwatch::get_file_sha256(*path);
        std::optional<std::string> md5 = reaperwatch::get_file_md5(*path);
        std::cout << "sha256:      " << (sha ? *sha : "<failed>") << "\n";
        std::cout << "md5:         " << (md5 ? *md5 : "<failed>") << "\n";

        reaperwatch::FileSignature sig = reaperwatch::get_file_signature(*path);
        std::cout << "signed:      " << sig.is_signed
                  << "  signer=" << (sig.signer ? *sig.signer : "<none>") << "\n";
    }

    return 0;
}
