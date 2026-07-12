add_executable(reaperwatch_agent main.cpp)

add_subdirectory(transport)
add_subdirectory(collectors)
add_subdirectory(detections)

# shell32 -> ShellExecuteExW, used to self-elevate via UAC when not already Administrator
target_link_libraries(reaperwatch_agent PRIVATE reaperwatch_collectors reaperwatch_detections reaperwatch_transport shell32)

