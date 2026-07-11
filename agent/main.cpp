#include "collectors/process_monitor.h"

int main() {
    // Live process telemetry: start the ETW consumer and stream a normalized
    // process_create event for every launch on the machine. Blocks until stopped.
    // Requires Administrator (kernel ETW sessions are privileged).
    reaperwatch::collect_process_events();
    return 0;
}
