#include <windows.h>
#include <shellapi.h>

#include <iostream>

#include "collectors/process_monitor.h"

namespace {

// Same TokenElevation check used for user.is_admin in T5's get_process_user,
// applied here to our own process instead of a target one.
bool is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    const bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

// Relaunch this same executable elevated, triggering the standard UAC prompt.
// Returns true if a new elevated instance was launched (the user accepted).
bool relaunch_elevated() {
    wchar_t exe_path[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, exe_path, MAX_PATH)) {
        return false;
    }
    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.lpVerb = L"runas";
    info.lpFile = exe_path;
    info.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&info);
}

}  // namespace

int main() {
    // Kernel ETW sessions require Administrator. Rather than silently failing
    // (and, when double-clicked, closing before anyone can read why), request
    // elevation ourselves: relaunch elevated via UAC and let this instance exit.
    if (!is_elevated()) {
        std::cerr << "ReaperWatch needs Administrator privileges for the kernel ETW session.\n";
        std::cerr << "Requesting elevation...\n";
        if (relaunch_elevated()) {
            return 0;
        }
        std::cerr << "Elevation was declined or failed. Re-run as Administrator.\n";
        std::cerr << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    // Live process telemetry: start the ETW consumer and stream a normalized
    // process_create event for every launch on the machine. Blocks until stopped.
    reaperwatch::collect_process_events();
    return 0;
}
