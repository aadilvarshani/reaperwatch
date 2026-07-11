#pragma once

#include <string>

#include "process_event.h"

namespace reaperwatch {

// Serialize a fully-enriched event to the normalized "process_create" JSON,
// pretty-printed. This is the single serialization boundary: nothing else in the
// codebase depends on the JSON library, so it can be swapped without churn.
std::string to_json_string(const ProcessEvent& event);

}  // namespace reaperwatch
