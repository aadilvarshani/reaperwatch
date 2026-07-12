#pragma once

#include <string>

namespace reaperwatch {

// Appends one compact, single-line JSON event to the durable event log at
// data/events.jsonl (JSON Lines format: one JSON object per line), creating
// the data/ directory on first use. Best-effort: a write failure is swallowed
// rather than crashing the sensor.
//
// This is the first piece of the planned transport layer. It writes
// synchronously on the caller's thread; a later revision will replace it with
// a lock-free queue and a background sender once telemetry volume warrants it.
void append_event_line(const std::string& json_line);

}  // namespace reaperwatch
