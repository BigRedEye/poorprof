cmake_minimum_required(VERSION 3.10)

include(cmake/variables.cmake)
include(cmake/dependencies/setup.cmake)

project(poorprof VERSION 0.1.0 LANGUAGES CXX)

include(cmake/common.cmake)
include(cmake/dependencies/populate.cmake)

add_subdirectory(src)
