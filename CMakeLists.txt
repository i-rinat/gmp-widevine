project(gmp-widevine)
cmake_minimum_required(VERSION 2.8.8)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fPIC -pthread -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror=implicit-function-declaration")

include_directories(.)

add_subdirectory(lib)
add_subdirectory(src)
