#define OPENREVERSE_EXTENSION_BUILD
#include <openreverse/extension.h>

#include <cstring>

namespace {

constexpr uint64_t kCapabilities = OPENREVERSE_CAPABILITY_PROJECT_EXTENSION_STATE;
constexpr char kState[] = "{\"schema\":1,\"value\":\"fixture\"}";

OpenReverseResult OPENREVERSE_CALL Initialize(const OpenReverseHostApi* host,
                                               void** extensionContext)
{
    if (!host || !extensionContext || host->struct_size < sizeof(OpenReverseHostApi) ||
        host->api_version != OPENREVERSE_EXTENSION_API_VERSION ||
        (host->granted_capabilities & kCapabilities) != kCapabilities)
        return OPENREVERSE_ERROR_INVALID_ARGUMENT;

    const OpenReverseStringView state{kState, static_cast<uint32_t>(std::strlen(kState)), 0};
    OpenReverseResult result = host->set_project_state(host->host_context, state);
    if (result != OPENREVERSE_OK) return result;

    char restored[64]{};
    uint32_t requiredSize = 0;
    result = host->get_project_state(host->host_context, restored, sizeof(restored),
                                     &requiredSize);
    if (result != OPENREVERSE_OK || requiredSize != sizeof(kState) ||
        std::strcmp(restored, kState) != 0)
        return OPENREVERSE_ERROR_INVALID_STATE;

    *extensionContext = nullptr;
    return OPENREVERSE_OK;
}

OpenReverseResult OPENREVERSE_CALL SessionChanged(void*, const OpenReverseSessionEvent*)
{
    return OPENREVERSE_ERROR_INTERNAL;
}

void OPENREVERSE_CALL Shutdown(void*) {}

} // namespace

extern "C" OPENREVERSE_EXTENSION_EXPORT OpenReverseResult OPENREVERSE_CALL
OpenReverseExtensionGetDescriptor(uint32_t requestedApiVersion,
                                  OpenReverseExtensionDescriptor* descriptor)
{
    if (!descriptor || descriptor->struct_size < sizeof(OpenReverseExtensionDescriptor))
        return OPENREVERSE_ERROR_INVALID_ARGUMENT;
    if (requestedApiVersion != OPENREVERSE_EXTENSION_API_VERSION)
        return OPENREVERSE_ERROR_UNSUPPORTED_API;

    OpenReverseExtensionDescriptor value{};
    value.struct_size = sizeof(value);
    value.api_version = OPENREVERSE_EXTENSION_API_VERSION;
    value.extension_version_major = 0;
    value.extension_version_minor = 1;
    value.extension_version_patch = 0;
    value.requested_capabilities = kCapabilities;
    value.initialize = Initialize;
    value.session_changed = SessionChanged;
    value.shutdown = Shutdown;
    *descriptor = value;
    return OPENREVERSE_OK;
}
