cmake_minimum_required(VERSION 3.6)
project(dnsspoofer_tests)

# https://raw.githubusercontent.com/bro/cmake/master/FindPCAP.cmake
# https://github.com/vast-io/vast/blob/master/cmake/FindPCAP.cmake
# or roll your own
include(FindPCAP.cmake)
SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
find_package(PCAP REQUIRED)
include_directories(${PCAP_INCLUDE_DIRS})
set(SOURCE_FILES
        test.cpp dns.cpp)
add_executable(dnsspoofer_tests ${SOURCE_FILES})
target_link_libraries(dnsspoofer_tests pcap)

add_subdirectory(firewall)
