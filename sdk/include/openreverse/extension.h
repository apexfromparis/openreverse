#ifndef OPENREVERSE_EXTENSION_H
#define OPENREVERSE_EXTENSION_H

#include <stdint.h>

#if defined(_WIN32)
#define OPENREVERSE_CALL __cdecl
#if defined(OPENREVERSE_EXTENSION_BUILD)
#define OPENREVERSE_EXTENSION_EXPORT __declspec(dllexport)
#else
#define OPENREVERSE_EXTENSION_EXPORT
#endif
#else
#define OPENREVERSE_CALL
#define OPENREVERSE_EXTENSION_EXPORT
#endif

#define OPENREVERSE_EXTENSION_API_VERSION 1u
#define OPENREVERSE_EXTENSION_ENTRYPOINT_NAME "OpenReverseExtensionGetDescriptor"

#define OPENREVERSE_CAPABILITY_ANALYSIS_READ          (UINT64_C(1) << 0)
#define OPENREVERSE_CAPABILITY_PROJECT_READ           (UINT64_C(1) << 1)
#define OPENREVERSE_CAPABILITY_PROJECT_EXTENSION_STATE (UINT64_C(1) << 2)
#define OPENREVERSE_CAPABILITY_NAVIGATION             (UINT64_C(1) << 3)
#define OPENREVERSE_CAPABILITY_UI_PANEL               (UINT64_C(1) << 4)
#define OPENREVERSE_CAPABILITY_UI_COMMAND             (UINT64_C(1) << 5)
#define OPENREVERSE_CAPABILITY_AI_ACTION              (UINT64_C(1) << 6)
#define OPENREVERSE_CAPABILITY_ANALYSIS_ACTION        (UINT64_C(1) << 7)
#define OPENREVERSE_CAPABILITY_FILESYSTEM             (UINT64_C(1) << 16)
#define OPENREVERSE_CAPABILITY_NETWORK                (UINT64_C(1) << 17)
#define OPENREVERSE_CAPABILITY_PROCESS_MEMORY         (UINT64_C(1) << 18)
#define OPENREVERSE_CAPABILITY_PROJECT_WRITE          (UINT64_C(1) << 19)

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 8)

typedef enum OpenReverseResult {
    OPENREVERSE_OK = 0,
    OPENREVERSE_ERROR_INVALID_ARGUMENT = 1,
    OPENREVERSE_ERROR_NOT_FOUND = 2,
    OPENREVERSE_ERROR_UNSUPPORTED_API = 3,
    OPENREVERSE_ERROR_NO_ACTIVE_SESSION = 4,
    OPENREVERSE_ERROR_NO_ACTIVE_PROJECT = 5,
    OPENREVERSE_ERROR_PERMISSION_DENIED = 6,
    OPENREVERSE_ERROR_BUFFER_TOO_SMALL = 7,
    OPENREVERSE_ERROR_DUPLICATE_ID = 8,
    OPENREVERSE_ERROR_INVALID_STATE = 9,
    OPENREVERSE_ERROR_INTERNAL = 10
} OpenReverseResult;

typedef enum OpenReverseArchitecture {
    OPENREVERSE_ARCHITECTURE_UNKNOWN = 0,
    OPENREVERSE_ARCHITECTURE_X86 = 1,
    OPENREVERSE_ARCHITECTURE_X64 = 2
} OpenReverseArchitecture;

typedef enum OpenReverseTargetTextField {
    OPENREVERSE_TARGET_TEXT_NAME = 1,
    OPENREVERSE_TARGET_TEXT_PATH = 2,
    OPENREVERSE_TARGET_TEXT_SHA256 = 3,
    OPENREVERSE_TARGET_TEXT_PROJECT_PATH = 4
} OpenReverseTargetTextField;

typedef struct OpenReverseStringView {
    const char* data;
    uint32_t length;
    uint32_t reserved;
} OpenReverseStringView;

typedef struct OpenReverseTargetInfo {
    uint32_t struct_size;
    uint32_t architecture;
    uint64_t image_base;
    uint64_t image_size;
    uint64_t current_address;
    uint64_t analysis_revision;
    uint32_t pe_timestamp;
    uint32_t function_count;
} OpenReverseTargetInfo;

#define OPENREVERSE_FUNCTION_BOUNDARY_KNOWN (1u << 0)

typedef struct OpenReverseFunctionInfo {
    uint32_t struct_size;
    uint32_t flags;
    uint64_t address;
    uint64_t rva;
    uint64_t size;
    uint32_t instruction_count;
    uint32_t basic_block_count;
    uint32_t direct_call_count;
    uint32_t reserved;
} OpenReverseFunctionInfo;

typedef struct OpenReverseSessionEvent {
    uint32_t struct_size;
    uint32_t has_active_target;
    uint64_t generation;
} OpenReverseSessionEvent;

typedef struct OpenReverseProjectEvent {
    uint32_t struct_size;
    uint32_t has_active_project;
    uint64_t reserved;
} OpenReverseProjectEvent;

typedef OpenReverseResult (OPENREVERSE_CALL *OpenReverseCommandExecuteCallback)(void* callback_context);
typedef OpenReverseResult (OPENREVERSE_CALL *OpenReverseCommandAvailableCallback)(
    void* callback_context, uint32_t* available);
typedef OpenReverseResult (OPENREVERSE_CALL *OpenReversePanelTextCallback)(
    void* callback_context, char* buffer, uint32_t capacity, uint32_t* required_size);

typedef struct OpenReverseCommandRegistration {
    uint32_t struct_size;
    uint32_t reserved;
    OpenReverseStringView command_id;
    OpenReverseStringView display_name;
    OpenReverseStringView category;
    OpenReverseCommandExecuteCallback execute;
    OpenReverseCommandAvailableCallback is_available;
    void* callback_context;
} OpenReverseCommandRegistration;

typedef struct OpenReversePanelRegistration {
    uint32_t struct_size;
    uint32_t default_visible;
    OpenReverseStringView panel_id;
    OpenReverseStringView title;
    OpenReversePanelTextCallback render_text;
    void* callback_context;
} OpenReversePanelRegistration;

typedef struct OpenReverseHostApi OpenReverseHostApi;

typedef OpenReverseResult (OPENREVERSE_CALL *OpenReverseInitializeCallback)(
    const OpenReverseHostApi* host_api, void** extension_context);
typedef OpenReverseResult (OPENREVERSE_CALL *OpenReverseSessionChangedCallback)(
    void* extension_context, const OpenReverseSessionEvent* event);
typedef OpenReverseResult (OPENREVERSE_CALL *OpenReverseProjectChangedCallback)(
    void* extension_context, const OpenReverseProjectEvent* event);
typedef void (OPENREVERSE_CALL *OpenReverseShutdownCallback)(void* extension_context);

struct OpenReverseHostApi {
    uint32_t struct_size;
    uint32_t api_version;
    uint32_t host_version_major;
    uint32_t host_version_minor;
    uint32_t host_version_patch;
    uint32_t reserved;
    uint64_t granted_capabilities;
    void* host_context;

    OpenReverseResult (OPENREVERSE_CALL *get_current_target)(
        void* host_context, OpenReverseTargetInfo* target);
    OpenReverseResult (OPENREVERSE_CALL *copy_target_text)(
        void* host_context, uint32_t field, char* buffer, uint32_t capacity,
        uint32_t* required_size);
    OpenReverseResult (OPENREVERSE_CALL *get_function_count)(
        void* host_context, uint32_t* count);
    OpenReverseResult (OPENREVERSE_CALL *get_function)(
        void* host_context, uint32_t index, OpenReverseFunctionInfo* function_info);
    OpenReverseResult (OPENREVERSE_CALL *copy_function_name)(
        void* host_context, uint32_t index, char* buffer, uint32_t capacity,
        uint32_t* required_size);
    OpenReverseResult (OPENREVERSE_CALL *navigate_to_address)(
        void* host_context, uint64_t address);
    OpenReverseResult (OPENREVERSE_CALL *get_project_state)(
        void* host_context, char* buffer, uint32_t capacity, uint32_t* required_size);
    OpenReverseResult (OPENREVERSE_CALL *set_project_state)(
        void* host_context, OpenReverseStringView json_object);
    OpenReverseResult (OPENREVERSE_CALL *register_command)(
        void* host_context, const OpenReverseCommandRegistration* registration);
    OpenReverseResult (OPENREVERSE_CALL *register_panel)(
        void* host_context, const OpenReversePanelRegistration* registration);
};

typedef struct OpenReverseExtensionDescriptor {
    uint32_t struct_size;
    uint32_t api_version;
    uint32_t extension_version_major;
    uint32_t extension_version_minor;
    uint32_t extension_version_patch;
    uint32_t reserved;
    uint64_t requested_capabilities;
    OpenReverseInitializeCallback initialize;
    OpenReverseSessionChangedCallback session_changed;
    OpenReverseProjectChangedCallback project_opened;
    OpenReverseProjectChangedCallback project_closed;
    OpenReverseShutdownCallback shutdown;
} OpenReverseExtensionDescriptor;

typedef OpenReverseResult (OPENREVERSE_CALL *OpenReverseGetDescriptorFunction)(
    uint32_t requested_api_version, OpenReverseExtensionDescriptor* descriptor);

OPENREVERSE_EXTENSION_EXPORT OpenReverseResult OPENREVERSE_CALL
OpenReverseExtensionGetDescriptor(uint32_t requested_api_version,
                                  OpenReverseExtensionDescriptor* descriptor);

#pragma pack(pop)

#ifdef __cplusplus
}

static_assert(sizeof(void*) == 8, "OpenReverse extension ABI v1 requires a 64-bit Windows target");
static_assert(sizeof(OpenReverseResult) == 4, "OpenReverseResult ABI layout changed");
static_assert(sizeof(OpenReverseArchitecture) == 4, "OpenReverseArchitecture ABI layout changed");
static_assert(sizeof(OpenReverseTargetTextField) == 4, "OpenReverseTargetTextField ABI layout changed");
static_assert(sizeof(OpenReverseStringView) == 16, "OpenReverseStringView ABI layout changed");
static_assert(sizeof(OpenReverseTargetInfo) == 48, "OpenReverseTargetInfo ABI layout changed");
static_assert(sizeof(OpenReverseFunctionInfo) == 48, "OpenReverseFunctionInfo ABI layout changed");
static_assert(sizeof(OpenReverseSessionEvent) == 16, "OpenReverseSessionEvent ABI layout changed");
static_assert(sizeof(OpenReverseProjectEvent) == 16, "OpenReverseProjectEvent ABI layout changed");
static_assert(sizeof(OpenReverseCommandRegistration) == 80,
              "OpenReverseCommandRegistration ABI layout changed");
static_assert(sizeof(OpenReversePanelRegistration) == 56,
              "OpenReversePanelRegistration ABI layout changed");
static_assert(sizeof(OpenReverseHostApi) == 120, "OpenReverseHostApi ABI layout changed");
static_assert(sizeof(OpenReverseExtensionDescriptor) == 72,
              "OpenReverseExtensionDescriptor ABI layout changed");
#endif

#endif
