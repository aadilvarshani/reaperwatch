#include "process_monitor.h"

#include <windows.h>
#include <evntrace.h>  // StartTrace, KERNEL_LOGGER_NAMEW, EVENT_TRACE_FLAG_PROCESS
#include <evntcons.h>  // EVENT_RECORD, PROCESS_TRACE_MODE_EVENT_RECORD
#include <tdh.h>       // TdhGetProperty (decode event payloads)

#include <atomic>
#include <iostream>
#include <optional>
#include <vector>

#include "event_json.h"

namespace reaperwatch {
namespace {

// The NT Kernel Logger control GUID. We start THIS session (rather than the
// Microsoft-Windows-Kernel-Process manifest provider, which does not deliver
// ProcessStart to a normal real-time session on recent builds) and turn on the
// PROCESS flag -- the classic, reliable source of process create/exit events.
const GUID kSystemTraceControlGuid = {
    0x9e814aad, 0x3204, 0x11d2, {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}};

// The kernel "Process" event GUID. Its events arrive with Opcode 1 = create,
// 2 = exit, 3/4 = rundown of already-running processes.
const GUID kProcessEventGuid = {
    0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};

const wchar_t kSessionName[] = KERNEL_LOGGER_NAMEW;  // L"NT Kernel Logger"

constexpr UCHAR kProcessCreateOpcode = 1;  // EVENT_TRACE_TYPE_START

// Extract a UInt32 payload field (e.g. "ProcessId") from an event via TDH.
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
    // Only the kernel Process events, and only brand-new creations (skip exit
    // and the startup rundown of already-running processes).
    if (!IsEqualGUID(record->EventHeader.ProviderId, kProcessEventGuid) ||
        record->EventHeader.EventDescriptor.Opcode != kProcessCreateOpcode) {
        return;
    }

    const std::optional<std::uint32_t> pid = get_event_u32(record, L"ProcessId");
    if (!pid) {
        return;
    }
    // Run the full enrichment pipeline and emit the normalized event. std::flush
    // so it appears immediately and survives an abrupt exit (redirected stdout is
    // fully buffered otherwise).
    std::cout << to_json_string(build_process_event(*pid)) << "\n\n" << std::flush;
}

// Build an EVENT_TRACE_PROPERTIES buffer for the kernel logger. The struct is
// immediately followed by room for the session name; re-zeroed each call.
std::vector<BYTE> make_session_props() {
    const size_t size = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(kSessionName);
    std::vector<BYTE> buffer(size, 0);
    auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
    p->Wnode.BufferSize = static_cast<ULONG>(size);
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1;                 // QPC (high-resolution) timestamps
    p->Wnode.Guid = kSystemTraceControlGuid;    // marks this as the kernel logger
    p->EnableFlags = EVENT_TRACE_FLAG_PROCESS;  // capture process create/exit
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    return buffer;
}

EVENT_TRACE_PROPERTIES* props_of(std::vector<BYTE>& b) {
    return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(b.data());
}

// The active session handle, so the Ctrl+C handler can stop it on the way out.
std::atomic<TRACEHANDLE> g_session{0};

// Stop the session on Ctrl+C so we don't leave the kernel logger running.
BOOL WINAPI on_ctrl_c(DWORD) {
    auto b = make_session_props();
    ControlTraceW(g_session.load(), kSessionName, props_of(b), EVENT_TRACE_CONTROL_STOP);
    return FALSE;  // fall through to the default handler, which terminates us
}

}  // namespace

// Start the kernel logger with the PROCESS flag and stream every process
// creation through the enrichment pipeline. Blocks until the session stops.
// Requires Administrator.
void collect_process_events() {
    // Stop any stale kernel-logger session first.
    { auto b = make_session_props();
      ControlTraceW(0, kSessionName, props_of(b), EVENT_TRACE_CONTROL_STOP); }

    // Controller: start the kernel logger. Retry once if it already exists.
    TRACEHANDLE session = 0;
    auto start_props = make_session_props();
    ULONG status = StartTraceW(&session, kSessionName, props_of(start_props));
    if (status == ERROR_ALREADY_EXISTS) {
        auto sp = make_session_props();
        ControlTraceW(0, kSessionName, props_of(sp), EVENT_TRACE_CONTROL_STOP);
        start_props = make_session_props();
        status = StartTraceW(&session, kSessionName, props_of(start_props));
    }
    if (status != ERROR_SUCCESS) {
        std::cerr << "StartTrace failed: " << status
                  << (status == ERROR_ACCESS_DENIED ? "  (run as Administrator)" : "")
                  << "\n";
        return;
    }
    g_session = session;
    SetConsoleCtrlHandler(on_ctrl_c, TRUE);
    // The kernel logger is enabled via EnableFlags above -- no EnableTraceEx2.

    // Consumer: open the session in real-time mode and attach our callback.
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
    ProcessTrace(&consumer, 1, nullptr, nullptr);  // blocks, driving on_event

    // Cleanup (reached when the session is stopped, e.g. via Ctrl+C).
    CloseTrace(consumer);
    auto b = make_session_props();
    ControlTraceW(session, kSessionName, props_of(b), EVENT_TRACE_CONTROL_STOP);
}

}  // namespace reaperwatch
