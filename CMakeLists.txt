# this is just for CLion
cmake_minimum_required(VERSION 3.6)
project(dns-spoofer)
find_package(PythonLibs REQUIRED)
include_directories(${PYTHON_INCLUDE_DIRS})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c11")

set(SOURCE_FILES
        dnsspoofer.c)

add_executable(dnsspoofer ${SOURCE_FILES})
