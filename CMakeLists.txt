cmake_minimum_required(VERSION 3.20)
project(Utils LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Header-only library
add_library(utils INTERFACE)
target_compile_features(utils INTERFACE cxx_std_23)
target_include_directories(utils INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# Dummy source so compile_commands.json is generated
add_executable(utils_compile_check compile_check.cpp)
target_link_libraries(utils_compile_check PRIVATE utils)
