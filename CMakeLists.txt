cmake_minimum_required(VERSION 3.20)
project(reaperwatch LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Statically link the MSVC C/C++ runtime so the agent has zero dependency on
# the Visual C++ Redistributable being installed on the target machine -- it
# must run standalone on a bare lab VM with nothing but Windows itself.
cmake_policy(SET CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_subdirectory(agent)
add_subdirectory(engine)

