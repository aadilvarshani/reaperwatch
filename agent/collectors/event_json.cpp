#include "event_json.h"

#include <nlohmann/json.hpp>

namespace reaperwatch {
namespace {

using json = nlohmann::json;

// std::optional<std::string> -> a JSON string, or JSON null when absent. Emitting
// null (rather than omitting the key) keeps every event the same shape.
json opt(const std::optional<std::string>& value) {
    return value.has_value() ? json(*value) : json(nullptr);
}

json build_json(const ProcessEvent& e) {
    json j;

    // Envelope.
    j["event_type"]  = e.event_type;
    j["timestamp"]   = e.timestamp;
    j["sequence_id"] = e.sequence_id;

    // The subject process. Note "signed" (not "is_signed") to match the schema.
    j["process"] = {
        {"pid", e.process.pid},
        {"name", e.process.name},
        {"path", opt(e.process.path)},
        {"cmdline", opt(e.process.cmdline)},
        {"sha256", opt(e.process.sha256)},
        {"md5", opt(e.process.md5)},
        {"signed", e.process.is_signed},
        {"signer", opt(e.process.signer)},
    };

    j["parent"] = {
        {"pid", e.parent.pid},
        {"name", e.parent.name},
        {"path", opt(e.parent.path)},
        {"cmdline", opt(e.parent.cmdline)},
        {"sha256", opt(e.parent.sha256)},
    };

    j["grandparent"] = {
        {"pid", e.grandparent.pid},
        {"name", e.grandparent.name},
    };

    j["user"] = {
        {"name", e.user.name},
        {"domain", e.user.domain},
        {"sid", e.user.sid},
        {"is_admin", e.user.is_admin},
        {"is_system", e.user.is_system},
    };

    j["host"] = {
        {"hostname", e.host.hostname},
        {"os", e.host.os},
        {"arch", e.host.arch},
    };

    j["flags"] = {
        {"is_lolbin", e.flags.is_lolbin},
        {"unusual_parent", e.flags.unusual_parent},
        {"is_hollow", e.flags.is_hollow},
        {"is_injected", e.flags.is_injected},
    };

    return j;
}

}  // namespace

std::string to_json_string(const ProcessEvent& e) {
    return build_json(e).dump(2);  // pretty-print, 2-space indent
}

std::string to_json_line(const ProcessEvent& e) {
    return build_json(e).dump();  // compact, single line -- safe for JSON Lines
}

}  // namespace reaperwatch
