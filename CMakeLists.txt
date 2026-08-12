cmake_minimum_required(VERSION 3.23)
project(OpenReverse VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

configure_file(
    src/app/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/openreverse_version.h
    @ONLY
)

set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "Disable git updates during build" FORCE)
include(FetchContent)

FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        83f668625ad45364de71d385aeb6a5dd04bee02e
)
FetchContent_MakeAvailable(imgui)

set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS  OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG        5.0.1
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(capstone)

FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(json)

add_library(imgui_lib STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
)
target_include_directories(imgui_lib PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)
target_link_libraries(imgui_lib PUBLIC d3d11 d3dcompiler dxgi)

file(GLOB_RECURSE OPENREVERSE_SOURCES CONFIGURE_DEPENDS src/*.cpp)

configure_file(installer/app.rc.in installer/app.rc @ONLY)

add_executable(OpenReverse WIN32
    ${OPENREVERSE_SOURCES}
    ${CMAKE_CURRENT_BINARY_DIR}/installer/app.rc
)

target_include_directories(OpenReverse PRIVATE
    src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
    ${capstone_SOURCE_DIR}/include
)

target_link_libraries(OpenReverse PRIVATE
    imgui_lib
    capstone
    nlohmann_json::nlohmann_json
    psapi
    dwmapi
    comdlg32
    winhttp
    advapi32
)

target_compile_definitions(OpenReverse PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

set_target_properties(OpenReverse PROPERTIES OUTPUT_NAME "OpenReverse")

set(OPENREVERSE_INSTALLER_PAYLOAD
    ${CMAKE_CURRENT_BINARY_DIR}/installer/OpenReverse.payload.exe
)
configure_file(installer/setup.rc.in installer/setup.rc @ONLY)

add_custom_command(
    OUTPUT ${OPENREVERSE_INSTALLER_PAYLOAD}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:OpenReverse>
        ${OPENREVERSE_INSTALLER_PAYLOAD}
    DEPENDS OpenReverse $<TARGET_FILE:OpenReverse>
    COMMENT "Preparing the OpenReverse installer payload"
    VERBATIM
)

set_source_files_properties(
    ${OPENREVERSE_INSTALLER_PAYLOAD}
    PROPERTIES GENERATED TRUE HEADER_FILE_ONLY TRUE
)
set_source_files_properties(
    ${CMAKE_CURRENT_BINARY_DIR}/installer/setup.rc
    PROPERTIES OBJECT_DEPENDS ${OPENREVERSE_INSTALLER_PAYLOAD}
)

add_executable(OpenReverse_Setup WIN32
    installer/setup_gui.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/installer/setup.rc
    ${OPENREVERSE_INSTALLER_PAYLOAD}
)

add_dependencies(OpenReverse_Setup OpenReverse)

target_include_directories(OpenReverse_Setup PRIVATE
    src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)

target_link_libraries(OpenReverse_Setup PRIVATE
    ole32
    shell32
    advapi32
    user32
    gdi32
    comctl32
    dwmapi
)

target_compile_definitions(OpenReverse_Setup PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

set_target_properties(OpenReverse_Setup PROPERTIES
    OUTPUT_NAME "OpenReverse-${PROJECT_VERSION}-Setup"
)

include(CTest)
if(BUILD_TESTING)
    add_executable(OpenReverseCoreTests
        tests/core_tests.cpp
        src/core/analysis_database.cpp
        src/core/analysis_scheduler.cpp
        src/core/data_analyzer.cpp
        src/core/disassembler.cpp
        src/core/function_analyzer.cpp
        src/core/memory_reader.cpp
        src/core/module_analyzer.cpp
        src/core/pattern_scanner.cpp
        src/core/pe_parser.cpp
        src/core/string_scanner.cpp
        src/core/xref_scanner.cpp
        src/utils/helpers.cpp
        src/utils/logger.cpp
    )
    target_include_directories(OpenReverseCoreTests PRIVATE
        src
        ${capstone_SOURCE_DIR}/include
    )
    target_link_libraries(OpenReverseCoreTests PRIVATE capstone psapi)
    target_compile_definitions(OpenReverseCoreTests PRIVATE
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    add_test(NAME OpenReverse.Core COMMAND OpenReverseCoreTests)

    add_executable(OpenReverseTestFixture tests/fixtures/crackme/hwid_crackme.cpp)
    set_target_properties(OpenReverseTestFixture PROPERTIES
        OUTPUT_NAME "OpenReverseTestFixture"
    )
endif()
