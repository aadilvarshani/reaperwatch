#pragma once

#include <string>

namespace reaperwatch {

// Best-effort: POST one JSON event line to a console over HTTP, authenticated
// with the given key (X-ReaperWatch-Key header). Failures (console down,
// wrong key, no network) are swallowed -- this must never crash or block the
// sensor; the local JSONL log is the durable record regardless.
void send_event_http(const std::string& host, int port, const std::string& api_key,
                     const std::string& json_line);

}  // namespace reaperwatch
