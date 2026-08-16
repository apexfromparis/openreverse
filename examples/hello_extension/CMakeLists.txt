cmake_minimum_required(VERSION 3.23)
project(OpenReverseHelloExtension VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT OPENREVERSE_SDK_INCLUDE_DIR)
    get_filename_component(OPENREVERSE_SDK_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/../../sdk/include" ABSOLUTE)
endif()

add_library(OpenReverseHelloExtension MODULE hello_extension.cpp)
target_include_directories(OpenReverseHelloExtension PRIVATE "${OPENREVERSE_SDK_INCLUDE_DIR}")
target_compile_definitions(OpenReverseHelloExtension PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
set_target_properties(OpenReverseHelloExtension PROPERTIES PREFIX "" OUTPUT_NAME "OpenReverseHelloExtension")
