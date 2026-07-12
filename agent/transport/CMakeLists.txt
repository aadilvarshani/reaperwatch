add_library(reaperwatch_transport event_sink.cpp config.cpp http_sender.cpp)

# ${CMAKE_SOURCE_DIR}/third_party holds vendored header-only deps (nlohmann/json),
# needed by config.cpp to parse reaperwatch.config.json.
target_include_directories(reaperwatch_transport PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/third_party
)

# winhttp -> WinHttpOpen/Connect/OpenRequest/SendRequest, the HTTP client used
# to push events to a console.
target_link_libraries(reaperwatch_transport PUBLIC winhttp)
