add_library(reaperwatch_collectors
    process_monitor.cpp
    file_monitor.cpp
    network_monitor.cpp
    registry_monitor.cpp
)

target_include_directories(reaperwatch_collectors PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

