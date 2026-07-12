#include "event_sink.h"

#include <filesystem>
#include <fstream>
#include <mutex>

namespace reaperwatch {
namespace {

// Fixed for now (single-machine, single-agent setup); revisit once the agent
// reads its own install/config location.
const std::filesystem::path kDataDir = "C:\\ReaperWatch\\data";
const std::filesystem::path kEventsFile = kDataDir / "events.jsonl";

// ETW could in principle invoke the callback from more than one thread; guard
// the shared file against interleaved writes.
std::mutex g_mutex;

}  // namespace

void append_event_line(const std::string& json_line) {
    std::lock_guard<std::mutex> lock(g_mutex);

    std::error_code ec;
    std::filesystem::create_directories(kDataDir, ec);  // no-op if it already exists

    // Reopen-per-call keeps this simple and crash-safe (no long-lived handle to
    // leak or corrupt); fine at process-creation rates.
    std::ofstream file(kEventsFile, std::ios::app | std::ios::binary);
    if (!file) {
        return;  // best-effort: never crash the sensor over a logging failure
    }
    file << json_line << '\n';
}

}  // namespace reaperwatch
