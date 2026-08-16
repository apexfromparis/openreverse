#define OPENREVERSE_EXTENSION_BUILD
#include <openreverse/extension.h>

#include <cstdio>
#include <cstring>
#include <new>
#include <string>

namespace {

constexpr uint64_t kCapabilities = OPENREVERSE_CAPABILITY_ANALYSIS_READ |
    OPENREVERSE_CAPABILITY_NAVIGATION |
    OPENREVERSE_CAPABILITY_UI_PANEL |
    OPENREVERSE_CAPABILITY_UI_COMMAND;

struct HelloContext {
    const OpenReverseHostApi* host = nullptr;
};

OpenReverseStringView View(const char* text)
{
    return {text, static_cast<uint32_t>(std::strlen(text)), 0};
}

OpenReverseResult WriteText(const std::string& text, char* buffer, uint32_t capacity,
                            uint32_t* requiredSize)
{
    if (!requiredSize) return OPENREVERSE_ERROR_INVALID_ARGUMENT;
    *requiredSize = static_cast<uint32_t>(text.size() + 1);
    if (!buffer || capacity < *requiredSize) return OPENREVERSE_ERROR_BUFFER_TOO_SMALL;
    std::memcpy(buffer, text.data(), text.size());
    buffer[text.size()] = '\0';
    return OPENREVERSE_OK;
}

OpenReverseResult OPENREVERSE_CALL CommandAvailable(void* context, uint32_t* available)
{
    if (!context || !available) return OPENREVERSE_ERROR_INVALID_ARGUMENT;
    const auto* hello = static_cast<HelloContext*>(context);
    uint32_t count = 0;
    const OpenReverseResult result = hello->host->get_function_count(
        hello->host->host_context, &count);
    *available = result == OPENREVERSE_OK && count != 0 ? 1u : 0u;
    return result;
}

OpenReverseResult OPENREVERSE_CALL NavigateToFirstFunction(void* context)
{
    if (!context) return OPENREVERSE_ERROR_INVALID_ARGUMENT;
    const auto* hello = static_cast<HelloContext*>(context);
    OpenReverseFunctionInfo function{};
    function.struct_size = sizeof(function);
    OpenReverseResult result = hello->host->get_function(
        hello->host->host_context, 0, &function);
    if (result != OPENREVERSE_OK) return result;
    return hello->host->navigate_to_address(hello->host->host_context, function.address);
}

OpenReverseResult OPENREVERSE_CALL RenderPanel(void* context, char* buffer,
                                               uint32_t capacity, uint32_t* requiredSize)
{
    if (!context) return OPENREVERSE_ERROR_INVALID_ARGUMENT;
    const auto* hello = static_cast<HelloContext*>(context);
    uint32_t functionCount = 0;
    const OpenReverseResult result = hello->host->get_function_count(
        hello->host->host_context, &functionCount);
    if (result == OPENREVERSE_ERROR_NO_ACTIVE_SESSION)
        return WriteText("No active target. Open a binary to inspect the function count.",
                         buffer, capacity, requiredSize);
    if (result != OPENREVERSE_OK) return result;
    return WriteText("Hello from the public OpenReverse SDK.\nDetected functions: " +
        std::to_string(functionCount), buffer, capacity, requiredSize);
}

OpenReverseResult OPENREVERSE_CALL Initialize(const OpenReverseHostApi* host,
                                               void** extensionContext)
{
    if (!host || !extensionContext || host->struct_size < sizeof(OpenReverseHostApi) ||
        host->api_version != OPENREVERSE_EXTENSION_API_VERSION ||
        (host->granted_capabilities & kCapabilities) != kCapabilities)
        return OPENREVERSE_ERROR_INVALID_ARGUMENT;
    auto* context = new (std::nothrow) HelloContext{host};
    if (!context) return OPENREVERSE_ERROR_INTERNAL;

    OpenReverseCommandRegistration command{};
    command.struct_size = sizeof(command);
    command.command_id = View("org.openreverse.hello.navigate-first");
    command.display_name = View("Navigate to first function");
    command.category = View("Example Extension");
    command.execute = NavigateToFirstFunction;
    command.is_available = CommandAvailable;
    command.callback_context = context;
    OpenReverseResult result = host->register_command(host->host_context, &command);
    if (result != OPENREVERSE_OK)
    {
        delete context;
        return result;
    }

    OpenReversePanelRegistration panel{};
    panel.struct_size = sizeof(panel);
    panel.panel_id = View("org.openreverse.hello.summary");
    panel.title = View("Hello Extension");
    panel.default_visible = 0;
    panel.render_text = RenderPanel;
    panel.callback_context = context;
    result = host->register_panel(host->host_context, &panel);
    if (result != OPENREVERSE_OK)
    {
        delete context;
        return result;
    }
    *extensionContext = context;
    return OPENREVERSE_OK;
}

OpenReverseResult OPENREVERSE_CALL SessionChanged(void*, const OpenReverseSessionEvent*)
{
    return OPENREVERSE_OK;
}

OpenReverseResult OPENREVERSE_CALL ProjectChanged(void*, const OpenReverseProjectEvent*)
{
    return OPENREVERSE_OK;
}

void OPENREVERSE_CALL Shutdown(void* context)
{
    delete static_cast<HelloContext*>(context);
}

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
    value.project_opened = ProjectChanged;
    value.project_closed = ProjectChanged;
    value.shutdown = Shutdown;
    *descriptor = value;
    return OPENREVERSE_OK;
}
