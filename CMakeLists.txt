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

set(OPENREVERSE_HAS_DIA OFF)
set(_openreverse_dia_roots)
if(DEFINED ENV{VSINSTALLDIR})
    list(APPEND _openreverse_dia_roots "$ENV{VSINSTALLDIR}/DIA SDK")
endif()
file(GLOB _openreverse_detected_dia_roots LIST_DIRECTORIES true
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/*/DIA SDK")
list(APPEND _openreverse_dia_roots ${_openreverse_detected_dia_roots})
foreach(_dia_root IN LISTS _openreverse_dia_roots)
    if(EXISTS "${_dia_root}/include/dia2.h" AND
       EXISTS "${_dia_root}/lib/amd64/diaguids.lib")
        set(OPENREVERSE_DIA_INCLUDE_DIR "${_dia_root}/include")
        set(OPENREVERSE_DIA_GUIDS_LIBRARY "${_dia_root}/lib/amd64/diaguids.lib")
        set(OPENREVERSE_DIA_RUNTIME "${_dia_root}/bin/amd64/msdia140.dll")
        set(OPENREVERSE_HAS_DIA ON)
        break()
    endif()
endforeach()
message(STATUS "OpenReverse DIA provider: ${OPENREVERSE_HAS_DIA}")

option(OPENREVERSE_ENABLE_MSVC_ANALYZE
    "Enable MSVC code analysis for first-party targets" OFF)

function(openreverse_enable_dia target_name)
    if(OPENREVERSE_HAS_DIA)
        target_include_directories(${target_name} PRIVATE ${OPENREVERSE_DIA_INCLUDE_DIR})
        target_link_libraries(${target_name} PRIVATE ${OPENREVERSE_DIA_GUIDS_LIBRARY} oleaut32)
        target_compile_definitions(${target_name} PUBLIC OPENREVERSE_HAS_DIA=1)
    else()
        target_compile_definitions(${target_name} PUBLIC OPENREVERSE_HAS_DIA=0)
    endif()
endfunction()

function(openreverse_enable_first_party_warnings target_name)
    target_compile_options(${target_name} PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/W4>)
    if(OPENREVERSE_ENABLE_MSVC_ANALYZE AND MSVC)
        target_compile_options(${target_name} PRIVATE /analyze)
    endif()
endfunction()

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

set(OPENREVERSE_CORE_SOURCES
    src/core/address_space.cpp
    src/core/analysis_database.cpp
    src/core/analysis_scheduler.cpp
    src/core/analysis_session.cpp
    src/core/binary_diff.cpp
    src/core/data_analyzer.cpp
    src/core/dia_symbol_provider.cpp
    src/core/disassembler.cpp
    src/core/dump_loader.cpp
    src/core/function_analyzer.cpp
    src/core/instruction_semantics.cpp
    src/core/memory_reader.cpp
    src/core/module_analyzer.cpp
    src/core/module_manager.cpp
    src/core/offset_model.cpp
    src/core/pattern_scanner.cpp
    src/core/pe_parser.cpp
    src/core/process_manager.cpp
    src/core/project.cpp
    src/core/signature_engine.cpp
    src/core/string_scanner.cpp
    src/core/version_intelligence.cpp
    src/core/xref_scanner.cpp
    src/utils/helpers.cpp
    src/utils/logger.cpp
)

add_library(OpenReverseCore STATIC ${OPENREVERSE_CORE_SOURCES})
target_include_directories(OpenReverseCore PUBLIC
    src
    sdk/include
    ${capstone_SOURCE_DIR}/include
)
target_link_libraries(OpenReverseCore PUBLIC
    capstone
    nlohmann_json::nlohmann_json
    psapi
    bcrypt
    dbghelp
)
target_compile_definitions(OpenReverseCore PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
)
openreverse_enable_dia(OpenReverseCore)
openreverse_enable_first_party_warnings(OpenReverseCore)

add_library(OpenReverseExtensions STATIC
    src/extensions/extension_manifest.cpp
    src/extensions/extension_manager.cpp
)
target_include_directories(OpenReverseExtensions PUBLIC src sdk/include)
target_link_libraries(OpenReverseExtensions PUBLIC nlohmann_json::nlohmann_json)
target_compile_definitions(OpenReverseExtensions PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
)
openreverse_enable_first_party_warnings(OpenReverseExtensions)

add_library(OpenReverseTextEditor STATIC src/ui/vendor/TextEditor.cpp)
target_include_directories(OpenReverseTextEditor PUBLIC src)
target_link_libraries(OpenReverseTextEditor PUBLIC imgui_lib)
target_compile_definitions(OpenReverseTextEditor PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
)

add_library(OpenReverseUI STATIC
    src/ui/panels/ai_copilot.cpp
    src/ui/panels/analysis_panel.cpp
    src/ui/panels/bookmarks_panel.cpp
    src/ui/panels/console_panel.cpp
    src/ui/panels/data_inspector.cpp
    src/ui/panels/disasm_view.cpp
    src/ui/panels/hex_editor.cpp
    src/ui/panels/memory_map.cpp
    src/ui/panels/modules_panel.cpp
    src/ui/panels/offsets_panel.cpp
    src/ui/panels/openreverse_editor.cpp
    src/ui/panels/pe_viewer.cpp
    src/ui/panels/process_list.cpp
    src/ui/panels/scanner_panel.cpp
    src/ui/panels/strings_panel.cpp
    src/ui/panels/version_intelligence_panel.cpp
    src/ui/ui_manager.cpp
)
target_include_directories(OpenReverseUI PUBLIC src)
target_link_libraries(OpenReverseUI PUBLIC OpenReverseCore OpenReverseTextEditor imgui_lib)
target_compile_definitions(OpenReverseUI PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
)
openreverse_enable_first_party_warnings(OpenReverseUI)

configure_file(installer/app.rc.in installer/app.rc @ONLY)

add_executable(OpenReverse WIN32
    src/main.cpp
    src/ai/ai_service.cpp
    src/app/application.cpp
    src/app/automator.cpp
    src/cli/cli_repl.cpp
    installer/app.manifest
    ${CMAKE_CURRENT_BINARY_DIR}/installer/app.rc
)

target_include_directories(OpenReverse PRIVATE
    src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)

target_link_libraries(OpenReverse PRIVATE
    OpenReverseCore
    OpenReverseExtensions
    OpenReverseUI
    dwmapi
    comdlg32
    winhttp
    advapi32
    bcrypt
    ws2_32
)

target_compile_definitions(OpenReverse PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
openreverse_enable_first_party_warnings(OpenReverse)

set_target_properties(OpenReverse PROPERTIES OUTPUT_NAME "OpenReverse")

add_executable(OpenReverseValidation tools/validation_main.cpp)
target_link_libraries(OpenReverseValidation PRIVATE OpenReverseCore)
target_compile_definitions(OpenReverseValidation PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
)
openreverse_enable_first_party_warnings(OpenReverseValidation)

if(OPENREVERSE_HAS_DIA AND EXISTS "${OPENREVERSE_DIA_RUNTIME}")
    add_custom_command(TARGET OpenReverse POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${OPENREVERSE_DIA_RUNTIME}" "$<TARGET_FILE_DIR:OpenReverse>/msdia140.dll"
        VERBATIM)
    set(OPENREVERSE_DIA_RESOURCE_LINE
        "102 RCDATA \"${OPENREVERSE_DIA_RUNTIME}\"")
    set(OPENREVERSE_INSTALLER_HAS_DIA 1)
else()
    set(OPENREVERSE_DIA_RESOURCE_LINE "")
    set(OPENREVERSE_INSTALLER_HAS_DIA 0)
endif()

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
    PROPERTIES OBJECT_DEPENDS "${OPENREVERSE_INSTALLER_PAYLOAD};${OPENREVERSE_DIA_RUNTIME}"
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
    OPENREVERSE_INSTALLS_DIA=${OPENREVERSE_INSTALLER_HAS_DIA}
)
openreverse_enable_first_party_warnings(OpenReverse_Setup)

set_target_properties(OpenReverse_Setup PROPERTIES
    OUTPUT_NAME "OpenReverse-${PROJECT_VERSION}-Setup"
)

include(CTest)
if(BUILD_TESTING)
    add_executable(OpenReverseCoreTests
        tests/core_tests.cpp
    )
    target_link_libraries(OpenReverseCoreTests PRIVATE
        OpenReverseCore
        OpenReverseExtensions
    )
    openreverse_enable_first_party_warnings(OpenReverseCoreTests)
    add_test(NAME OpenReverse.Core COMMAND OpenReverseCoreTests)

    add_executable(OpenReverseTestFixture tests/fixtures/crackme/hwid_crackme.cpp)
    openreverse_enable_first_party_warnings(OpenReverseTestFixture)
    target_compile_options(OpenReverseTestFixture PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/Zi>)
    target_link_options(OpenReverseTestFixture PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/DEBUG:FULL>)
    set_target_properties(OpenReverseTestFixture PROPERTIES
        OUTPUT_NAME "OpenReverseTestFixture"
    )
    if(OPENREVERSE_HAS_DIA AND EXISTS "${OPENREVERSE_DIA_RUNTIME}")
        add_custom_command(TARGET OpenReverseCoreTests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${OPENREVERSE_DIA_RUNTIME}" "$<TARGET_FILE_DIR:OpenReverseCoreTests>/msdia140.dll"
            VERBATIM)
    endif()
    add_test(NAME OpenReverse.StaticOpen
        COMMAND powershell -NoProfile -ExecutionPolicy Bypass
            -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/static_open_test.ps1
            -Application $<TARGET_FILE:OpenReverse>
            -Fixture $<TARGET_FILE:OpenReverseTestFixture>
    )
    add_test(NAME OpenReverse.CorpusValidation
        COMMAND powershell -NoProfile -ExecutionPolicy Bypass
            -File ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus_validation_test.ps1
            -Validator $<TARGET_FILE:OpenReverseValidation>
            -Fixture $<TARGET_FILE:OpenReverseTestFixture>
    )

    add_library(OpenReverseHelloExtension MODULE
        examples/hello_extension/hello_extension.cpp
    )
    target_include_directories(OpenReverseHelloExtension PRIVATE sdk/include)
    target_compile_definitions(OpenReverseHelloExtension PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    set_target_properties(OpenReverseHelloExtension PROPERTIES
        PREFIX ""
        OUTPUT_NAME "OpenReverseHelloExtension"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/sdk-examples"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/sdk-examples"
    )

    add_library(OpenReverseMissingEntrypointExtension MODULE
        tests/fixtures/extensions/missing_entrypoint.cpp
    )
    set_target_properties(OpenReverseMissingEntrypointExtension PROPERTIES
        PREFIX ""
        OUTPUT_NAME "OpenReverseMissingEntrypointExtension"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test-extensions"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test-extensions"
    )

    add_library(OpenReverseFailingExtension MODULE
        tests/fixtures/extensions/failing_extension.cpp
    )
    target_include_directories(OpenReverseFailingExtension PRIVATE sdk/include)
    target_compile_definitions(OpenReverseFailingExtension PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    set_target_properties(OpenReverseFailingExtension PROPERTIES
        PREFIX ""
        OUTPUT_NAME "OpenReverseFailingExtension"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test-extensions"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test-extensions"
    )

    add_library(OpenReverseStateExtension MODULE
        tests/fixtures/extensions/state_extension.cpp
    )
    target_include_directories(OpenReverseStateExtension PRIVATE sdk/include)
    target_compile_definitions(OpenReverseStateExtension PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    set_target_properties(OpenReverseStateExtension PROPERTIES
        PREFIX ""
        OUTPUT_NAME "OpenReverseStateExtension"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test-extensions"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test-extensions"
    )

    add_dependencies(OpenReverseCoreTests OpenReverseTestFixture OpenReverseHelloExtension
        OpenReverseMissingEntrypointExtension OpenReverseFailingExtension
        OpenReverseStateExtension)
    add_dependencies(OpenReverseValidation OpenReverseTestFixture)
    target_compile_definitions(OpenReverseCoreTests PRIVATE
        OPENREVERSE_TEST_HELLO_EXTENSION="$<TARGET_FILE:OpenReverseHelloExtension>"
        OPENREVERSE_TEST_MISSING_ENTRYPOINT_EXTENSION="$<TARGET_FILE:OpenReverseMissingEntrypointExtension>"
        OPENREVERSE_TEST_FAILING_EXTENSION="$<TARGET_FILE:OpenReverseFailingExtension>"
        OPENREVERSE_TEST_STATE_EXTENSION="$<TARGET_FILE:OpenReverseStateExtension>"
        OPENREVERSE_TEST_HELLO_MANIFEST="${CMAKE_CURRENT_SOURCE_DIR}/examples/hello_extension/manifest.json"
        OPENREVERSE_TEST_FIXTURE_EXE="$<TARGET_FILE:OpenReverseTestFixture>"
        OPENREVERSE_TEST_FIXTURE_PDB="$<TARGET_PDB_FILE:OpenReverseTestFixture>"
    )
endif()
