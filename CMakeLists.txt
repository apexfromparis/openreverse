cmake_minimum_required(VERSION 3.20)
project(OpenReverse VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ─── Fetch Dependencies ───────────────────────────────────────────────────────
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "Disable git updates during build" FORCE)
include(FetchContent)

# Dear ImGui (docking branch for multi-panel layout)
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        docking
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(imgui)

# Capstone disassembly engine
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS  OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG        5.0.1
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(capstone)

# JSON for modern C++ (for config/bookmarks persistence)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(json)

# ─── ImGui static library (no CMakeLists in ImGui repo) ───────────────────────
add_library(imgui_lib STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
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

# ─── OpenReverse executable ────────────────────────────────────────────────────
file(GLOB_RECURSE OPENREVERSE_SOURCES CONFIGURE_DEPENDS src/*.cpp)

add_executable(OpenReverse WIN32 ${OPENREVERSE_SOURCES} installer/app.rc)

target_include_directories(OpenReverse PRIVATE
    src
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

# ─── OpenReverse Studio GUI setup installer ────────────────────────────────────
configure_file(installer/setup.rc.in installer/setup.rc @ONLY)

add_executable(OpenReverse_Setup WIN32 installer/setup_gui.cpp ${CMAKE_CURRENT_BINARY_DIR}/installer/setup.rc)

add_dependencies(OpenReverse_Setup OpenReverse)

target_include_directories(OpenReverse_Setup PRIVATE src)

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
    OUTPUT_NAME "OpenReverse_Studio_Setup_v2.0"
)
