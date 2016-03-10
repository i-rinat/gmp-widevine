project(gmp-widevine)
cmake_minimum_required(VERSION 2.8.8)

find_package(Boost 1.30 REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fPIC -pthread -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror=implicit-function-declaration")

include_directories(.)

include_directories("${Boost_INCLUDE_DIRS}")

add_subdirectory(lib)
add_subdirectory(src)
