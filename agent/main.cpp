#include <windows.h>

#include <iostream>

#include "collectors/event_json.h"
#include "collectors/process_monitor.h"

int main() {
    // Self-test: build and serialize a process_create event for our own process.
    // Once ETW is wired up (T10), this same pipeline runs on every real launch.
    const std::uint32_t my_pid = GetCurrentProcessId();
    const reaperwatch::ProcessEvent event = reaperwatch::build_process_event(my_pid);
    std::cout << reaperwatch::to_json_string(event) << "\n";
    return 0;
}
