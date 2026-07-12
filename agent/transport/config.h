#pragma once

#include <optional>
#include <string>

namespace reaperwatch {

// Where to send events over the network, and the key that authenticates us
// to that console. Loaded from reaperwatch.config.json sitting next to this
// executable -- NOT hardcoded, so a downloaded agent does nothing over the
// network until someone explicitly points it at their own console.
struct NetworkConfig {
    std::string host;
    int         port = 3000;
    std::string api_key;
};

// Loads the config once (cached for the process lifetime). std::nullopt when
// no config file is present, or it is malformed -- network sending is then
// simply skipped; the local JSONL log is unaffected either way.
std::optional<NetworkConfig> get_network_config();

}  // namespace reaperwatch
