#include "process_monitor.h"

#include <windows.h>
#include <evntrace.h>  // StartTrace, EnableTraceEx2, OpenTrace, ProcessTrace
#include <evntcons.h>  // EVENT_RECORD, PROCESS_TRACE_MODE_EVENT_RECORD
#include <tdh.h>       // TdhGetProperty (decode event payloads)

#include <cstring>
#include <iostream>
#include <optional>
#include <vector>

#include "event_json.h"

namespace reaperwatch {
namespace {

// Microsoft-Windows-Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}.
const GUID kKernelProcessGuid = {
    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

const wchar_t kSessionName[] = L"ReaperWatchKernelProcess";

// In the Kernel-Process manifest, ProcessStart is event id 1.
constexpr USHORT kProcessStartEventId = 1;

// Keyword selecting process start/stop events (WINEVENT_KEYWORD_PROCESS).
constexpr ULONGLONG kProcessKeyword = 0x10;

// Extract a UInt32 payload field (e.g. "ProcessID") from an event via TDH. TDH
// resolves the field by name using the provider's registered manifest.
std::optional<std::uint32_t> get_event_u32(PEVENT_RECORD record, PCWSTR name) {
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(name);
    desc.ArrayIndex = ULONG_MAX;
    std::uint32_t value = 0;
    if (TdhGetProperty(record, 0, nullptr, 1, &desc, sizeof(value),
                       reinterpret_cast<PBYTE>(&value)) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    return value;
}

// ProcessTrace calls this once per event in the session.
void WINAPI on_event(PEVENT_RECORD record) {
    // Only react to ProcessStart events (event id 1 in the Kernel-Process manifest).
    if (record->EventHeader.EventDescriptor.Id != kProcessStartEventId) {
        return;
    }
    // The new process's PID is a payload field; decode it via TDH.
    const std::optional<std::uint32_t> pid = get_event_u32(record, L"ProcessID");
    if (!pid) {
        return;
    }
    // Run the full T2-T9 enrichment pipeline and emit the normalized event.
    std::cout << to_json_string(build_process_event(*pid)) << "\n\n";
}

// Build an EVENT_TRACE_PROPERTIES buffer (the struct is immediately followed by
// space for the session name). Re-zeroed each call so it is safe to reuse.
std::vector<BYTE> make_session_props() {
    const size_t size = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(kSessionName);
    std::vector<BYTE> buffer(size, 0);
    auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    p->Wnode.BufferSize = static_cast<ULONG>(size);
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1;  // QPC (high-resolution) timestamps
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    return buffer;
}

EVENT_TRACE_PROPERTIES* props_of(std::vector<BYTE>& b) {
    return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(b.data());
}

}  // namespace

// Start a real-time ETW session on the Kernel-Process provider and stream every
// process launch through the enrichment pipeline. Blocks until the session stops.
// Requires Administrator (kernel ETW sessions are privileged).
void collect_process_events() {
    // A previous run may have left the session running; stop any stale one first.
    { auto b = make_session_props();
      ControlTraceW(0, kSessionName, props_of(b), EVENT_TRACE_CONTROL_STOP); }

    // ① Controller: start our session.
    auto start_props = make_session_props();
    TRACEHANDLE session = 0;
    ULONG status = StartTraceW(&session, kSessionName, props_of(start_props));
    if (status != ERROR_SUCCESS) {
        std::cerr << "StartTrace failed: " << status
                  << (status == ERROR_ACCESS_DENIED ? "  (run as Administrator)" : "")
                  << "\n";
        return;
    }

    // Subscribe the session to the Kernel-Process provider (process keyword).
    status = EnableTraceEx2(session, &kKernelProcessGuid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, kProcessKeyword, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        std::cerr << "EnableTraceEx2 failed: " << status << "\n";
        auto b = make_session_props();
        ControlTraceW(session, kSessionName, props_of(b), EVENT_TRACE_CONTROL_STOP);
        return;
    }

    // ② Consumer: open the session in real-time mode and attach our callback.
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(kSessionName);
    logfile.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = &on_event;

    TRACEHANDLE consumer = OpenTraceW(&logfile);
    if (consumer == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "OpenTrace failed: " << GetLastError() << "\n";
        auto b = make_session_props();
        ControlTraceW(session, kSessionName, props_of(b), EVENT_TRACE_CONTROL_STOP);
        return;
    }

    std::cerr << "ReaperWatch: listening for process launches (Ctrl+C to stop)...\n\n";
    ProcessTrace(&consumer, 1, nullptr, nullptr);  // ③ blocks, driving on_event

    // Cleanup (reached if the session is stopped externally).
    CloseTrace(consumer);
    auto b = make_session_props();
    ControlTraceW(session, kSessionName, props_of(b), EVENT_TRACE_CONTROL_STOP);
}

}  // namespace reaperwatch
