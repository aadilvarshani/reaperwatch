#include "config.h"

#include <windows.h>

#include <fstream>

#include <nlohmann/json.hpp>

namespace reaperwatch {
namespace {

// The directory this running executable lives in, as UTF-8 -- so the config
// file is found next to wherever the exe was copied to, not some fixed path.
std::string exe_directory() {
    wchar_t path[MAX_PATH];
    const DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (len == 0) {
        return {};
    }
    std::wstring wpath(path, len);
    const size_t slash = wpath.find_last_of(L"\\/");
    const std::wstring dir = (slash == std::wstring::npos) ? L"." : wpath.substr(0, slash);

    const int size = WideCharToMultiByte(CP_UTF8, 0, dir.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, dir.c_str(), -1, out.data(), size, nullptr, nullptr);
    return out;
}

std::optional<NetworkConfig> load_config_from_disk() {
    const std::string path = exe_directory() + "\\reaperwatch.config.json";
    std::ifstream file(path);
    if (!file) {
        return std::nullopt;  // no config file -- local-only mode, the default
    }

    try {
        nlohmann::json j;
        file >> j;
        NetworkConfig cfg;
        cfg.host    = j.at("console_host").get<std::string>();
        cfg.port    = j.value("console_port", 3000);
        cfg.api_key = j.at("api_key").get<std::string>();
        if (cfg.host.empty() || cfg.api_key.empty()) {
            return std::nullopt;
        }
        return cfg;
    } catch (const std::exception&) {
        return std::nullopt;  // malformed config -- fail safe to local-only
    }
}

}  // namespace

std::optional<NetworkConfig> get_network_config() {
    static const std::optional<NetworkConfig> cached = load_config_from_disk();
    return cached;
}

}  // namespace reaperwatch
