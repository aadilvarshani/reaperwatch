#pragma once

#include <string>

#include "process_event.h"

namespace reaperwatch {

// Serialize a fully-enriched event to the normalized "process_create" JSON,
// pretty-printed (for console/human display). This is the single serialization
// boundary: nothing else in the codebase depends on the JSON library, so it can
// be swapped without churn.
std::string to_json_string(const ProcessEvent& event);

// Same event, serialized as compact single-line JSON (no embedded newlines) --
// the shape required for JSON Lines files, where each line is one record.
std::string to_json_line(const ProcessEvent& event);

}  // namespace reaperwatch
