cmake_minimum_required(VERSION 3.16)
project(tsm_edge_host LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# wasmtime C API (precompiled). Override with -DWASMTIME_DIR=...
set(WASMTIME_DIR "/opt/wasmtime-c-api" CACHE PATH "wasmtime C API install dir")

add_executable(edge_host src/edge_host.cpp)
target_compile_options(edge_host PRIVATE -Wall -Wextra)
target_include_directories(edge_host PRIVATE ${WASMTIME_DIR}/include)

# Static libwasmtime needs the usual system libs on Linux.
target_link_libraries(edge_host PRIVATE
  ${WASMTIME_DIR}/lib/libwasmtime.a
  pthread dl m)
