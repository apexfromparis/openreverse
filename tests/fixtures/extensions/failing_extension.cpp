#define OPENREVERSE_EXTENSION_BUILD
#include <openreverse/extension.h>

namespace {

OpenReverseResult OPENREVERSE_CALL Initialize(const OpenReverseHostApi*, void**)
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
    value.initialize = Initialize;
    value.shutdown = Shutdown;
    *descriptor = value;
    return OPENREVERSE_OK;
}
