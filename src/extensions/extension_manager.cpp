#include "extension_manager.h"

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cctype>
#include <cwctype>
#include <cstring>
#include <limits>
#include <set>
#include <thread>
#include <utility>

namespace openreverse::extensions {

namespace {

constexpr uint32_t kMaximumCallbackTextBytes = 64 * 1024;
constexpr uint32_t kMaximumRegistrationIdBytes = 128;
constexpr uint32_t kMaximumRegistrationTextBytes = 256;

struct ModuleGuard {
    HMODULE handle = nullptr;
    ~ModuleGuard() { if (handle) FreeLibrary(handle); }
};

std::string WindowsError(const char* operation, DWORD code)
{
    return std::string(operation) + " failed with Windows error " + std::to_string(code);
}

bool IsValidUtf8(const std::string& value)
{
    if (value.empty()) return true;
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0) > 0;
}

bool CopyView(OpenReverseStringView view, uint32_t maximumLength, bool required,
              std::string& output)
{
    if (view.length > maximumLength || (view.length != 0 && view.data == nullptr)) return false;
    output.assign(view.data ? view.data : "", view.length);
    return (!required || !output.empty()) && output.find('\0') == std::string::npos &&
        IsValidUtf8(output);
}

bool ValidRegistrationId(const std::string& extensionId, const std::string& id)
{
    if (id.size() > kMaximumRegistrationIdBytes ||
        id.rfind(extensionId + ".", 0) != 0 || id.back() == '.') return false;
    for (unsigned char character : id)
        if (!(std::islower(character) || std::isdigit(character) || character == '.' ||
              character == '-' || character == '_')) return false;
    return true;
}

OpenReverseResult CopyOutput(const std::string& value, char* buffer, uint32_t capacity,
                             uint32_t* requiredSize)
{
    if (!requiredSize || value.size() >= (std::numeric_limits<uint32_t>::max)())
        return OPENREVERSE_ERROR_INVALID_ARGUMENT;
    const uint32_t required = static_cast<uint32_t>(value.size() + 1);
    *requiredSize = required;
    if (!buffer || capacity < required) return OPENREVERSE_ERROR_BUFFER_TOO_SMALL;
    std::memcpy(buffer, value.data(), value.size());
    buffer[value.size()] = '\0';
    return OPENREVERSE_OK;
}

bool SameDirectory(const std::filesystem::path& left, const std::filesystem::path& right)
{
    std::wstring leftText = std::filesystem::weakly_canonical(left).wstring();
    std::wstring rightText = std::filesystem::weakly_canonical(right).wstring();
    std::transform(leftText.begin(), leftText.end(), leftText.begin(),
        [](wchar_t value) { return static_cast<wchar_t>(std::towlower(value)); });
    std::transform(rightText.begin(), rightText.end(), rightText.begin(),
        [](wchar_t value) { return static_cast<wchar_t>(std::towlower(value)); });
    return leftText == rightText;
}

} // namespace

struct ExtensionManager::Impl {
    struct LoadedExtension;

    struct HostContext {
        Impl* manager = nullptr;
        LoadedExtension* extension = nullptr;
    };

    struct CommandRecord {
        ExtensionCommandInfo info;
        OpenReverseCommandExecuteCallback execute = nullptr;
        OpenReverseCommandAvailableCallback available = nullptr;
        void* callbackContext = nullptr;
    };

    struct PanelRecord {
        ExtensionPanelInfo info;
        OpenReversePanelTextCallback render = nullptr;
        void* callbackContext = nullptr;
    };

    struct LoadedExtension {
        ExtensionManifest manifest;
        HMODULE module = nullptr;
        OpenReverseExtensionDescriptor descriptor{};
        void* extensionContext = nullptr;
        HostContext hostContext;
        OpenReverseHostApi hostApi{};
        bool initializing = false;
        std::vector<CommandRecord> commands;
        std::vector<PanelRecord> panels;
    };

    ExtensionHostServices services;
    SemanticVersion hostVersion;
    std::thread::id ownerThread = std::this_thread::get_id();
    std::vector<std::unique_ptr<LoadedExtension>> loaded;
    std::vector<ExtensionDiagnostic> diagnostics;
    bool configured = false;
    bool discoveryStarted = false;
    bool shuttingDown = false;

    static Impl* Manager(void* context)
    {
        const auto* host = static_cast<HostContext*>(context);
        return host ? host->manager : nullptr;
    }

    static LoadedExtension* Extension(void* context)
    {
        const auto* host = static_cast<HostContext*>(context);
        return host ? host->extension : nullptr;
    }

    static bool HasCapability(LoadedExtension* extension, uint64_t capability)
    {
        return extension && (extension->manifest.capabilities & capability) != 0;
    }

    static bool OnOwnerThread(Impl* manager)
    {
        return manager && manager->ownerThread == std::this_thread::get_id();
    }

    static OpenReverseResult OPENREVERSE_CALL GetCurrentTarget(
        void* context, OpenReverseTargetInfo* target)
    {
        Impl* manager = Manager(context);
        LoadedExtension* extension = Extension(context);
        if (!OnOwnerThread(manager) || !target ||
            target->struct_size < sizeof(OpenReverseTargetInfo))
            return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        if (!HasCapability(extension, OPENREVERSE_CAPABILITY_ANALYSIS_READ))
            return OPENREVERSE_ERROR_PERMISSION_DENIED;
        ExtensionTargetSnapshot snapshot;
        if (!manager->services.currentTarget || !manager->services.currentTarget(snapshot))
            return OPENREVERSE_ERROR_NO_ACTIVE_SESSION;
        target->architecture = snapshot.architecture;
        target->image_base = snapshot.imageBase;
        target->image_size = snapshot.imageSize;
        target->current_address = snapshot.currentAddress;
        target->analysis_revision = snapshot.analysisRevision;
        target->pe_timestamp = snapshot.peTimestamp;
        target->function_count = snapshot.functionCount;
        return OPENREVERSE_OK;
    }

    static OpenReverseResult OPENREVERSE_CALL CopyTargetText(
        void* context, uint32_t field, char* buffer, uint32_t capacity, uint32_t* requiredSize)
    {
        Impl* manager = Manager(context);
        LoadedExtension* extension = Extension(context);
        if (!OnOwnerThread(manager)) return OPENREVERSE_ERROR_INVALID_STATE;
        if (field == OPENREVERSE_TARGET_TEXT_PROJECT_PATH)
        {
            if (!HasCapability(extension, OPENREVERSE_CAPABILITY_PROJECT_READ))
                return OPENREVERSE_ERROR_PERMISSION_DENIED;
            if (!manager->services.hasProject || !manager->services.hasProject())
                return OPENREVERSE_ERROR_NO_ACTIVE_PROJECT;
            return CopyOutput(manager->services.projectPath ? manager->services.projectPath() : "",
                              buffer, capacity, requiredSize);
        }
        if (!HasCapability(extension, OPENREVERSE_CAPABILITY_ANALYSIS_READ))
            return OPENREVERSE_ERROR_PERMISSION_DENIED;
        ExtensionTargetSnapshot snapshot;
        if (!manager->services.currentTarget || !manager->services.currentTarget(snapshot))
            return OPENREVERSE_ERROR_NO_ACTIVE_SESSION;
        switch (field)
        {
        case OPENREVERSE_TARGET_TEXT_NAME:
            return CopyOutput(snapshot.name, buffer, capacity, requiredSize);
        case OPENREVERSE_TARGET_TEXT_PATH:
            return CopyOutput(snapshot.path, buffer, capacity, requiredSize);
        case OPENREVERSE_TARGET_TEXT_SHA256:
            return CopyOutput(snapshot.sha256, buffer, capacity, requiredSize);
        default:
            return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        }
    }

    static OpenReverseResult OPENREVERSE_CALL GetFunctionCount(void* context, uint32_t* count)
    {
        Impl* manager = Manager(context);
        LoadedExtension* extension = Extension(context);
        if (!OnOwnerThread(manager)) return OPENREVERSE_ERROR_INVALID_STATE;
        if (!count) return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        if (!HasCapability(extension, OPENREVERSE_CAPABILITY_ANALYSIS_READ))
            return OPENREVERSE_ERROR_PERMISSION_DENIED;
        ExtensionTargetSnapshot snapshot;
        if (!manager->services.currentTarget || !manager->services.currentTarget(snapshot))
            return OPENREVERSE_ERROR_NO_ACTIVE_SESSION;
        *count = snapshot.functionCount;
        return OPENREVERSE_OK;
    }

    static OpenReverseResult OPENREVERSE_CALL GetFunction(
        void* context, uint32_t index, OpenReverseFunctionInfo* output)
    {
        Impl* manager = Manager(context);
        LoadedExtension* extension = Extension(context);
        if (!OnOwnerThread(manager)) return OPENREVERSE_ERROR_INVALID_STATE;
        if (!output || output->struct_size < sizeof(OpenReverseFunctionInfo))
            return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        if (!HasCapability(extension, OPENREVERSE_CAPABILITY_ANALYSIS_READ))
            return OPENREVERSE_ERROR_PERMISSION_DENIED;
        ExtensionFunctionSnapshot function;
        if (!manager->services.functionByIndex || !manager->services.functionByIndex(index, function))
            return OPENREVERSE_ERROR_NOT_FOUND;
        output->flags = function.boundaryKnown ? OPENREVERSE_FUNCTION_BOUNDARY_KNOWN : 0;
        output->address = function.address;
        output->rva = function.rva;
        output->size = function.size;
        output->instruction_count = function.instructionCount;
        output->basic_block_count = function.basicBlockCount;
        output->direct_call_count = function.directCallCount;
        output->reserved = 0;
        return OPENREVERSE_OK;
    }

    static OpenReverseResult OPENREVERSE_CALL CopyFunctionName(
        void* context, uint32_t index, char* buffer, uint32_t capacity, uint32_t* requiredSize)
    {
        Impl* manager = Manager(context);
        LoadedExtension* extension = Extension(context);
        if (!OnOwnerThread(manager)) return OPENREVERSE_ERROR_INVALID_STATE;
        if (!HasCapability(extension, OPENREVERSE_CAPABILITY_ANALYSIS_READ))
            return OPENREVERSE_ERROR_PERMISSION_DENIED;
        ExtensionFunctionSnapshot function;
        if (!manager->services.functionByIndex || !manager->services.functionByIndex(index, function))
            return OPENREVERSE_ERROR_NOT_FOUND;
        return CopyOutput(function.name, buffer, capacity, requiredSize);
    }

    static OpenReverseResult OPENREVERSE_CALL NavigateToAddress(void* context, uint64_t address)
    {
        Impl* manager = Manager(context);
        LoadedExtension* extension = Extension(context);
        if (!OnOwnerThread(manager)) return OPENREVERSE_ERROR_INVALID_STATE;
        if (address == 0) return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        if (!HasCapability(extension, OPENREVERSE_CAPABILITY_NAVIGATION))
            return OPENREVERSE_ERROR_PERMISSION_DENIED;
        if (!manager->services.navigateToAddress) return OPENREVERSE_ERROR_INVALID_STATE;
        return manager->services.navigateToAddress(address)
            ? OPENREVERSE_OK : OPENREVERSE_ERROR_NOT_FOUND;
    }

    static OpenReverseResult OPENREVERSE_CALL GetProjectState(
        void* context, char* buffer, uint32_t capacity, uint32_t* requiredSize)
    {
        Impl* manager = Manager(context);
        LoadedExtension* extension = Extension(context);
        if (!OnOwnerThread(manager)) return OPENREVERSE_ERROR_INVALID_STATE;
        if (!extension) return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        if (!HasCapability(extension, OPENREVERSE_CAPABILITY_PROJECT_EXTENSION_STATE))
            return OPENREVERSE_ERROR_PERMISSION_DENIED;
        if (!manager->services.hasProject || !manager->services.hasProject())
            return OPENREVERSE_ERROR_NO_ACTIVE_PROJECT;
        std::string state;
        if (!manager->services.getExtensionState ||
            !manager->services.getExtensionState(extension->manifest.id, state))
            return OPENREVERSE_ERROR_NOT_FOUND;
        return CopyOutput(state, buffer, capacity, requiredSize);
    }

    static OpenReverseResult OPENREVERSE_CALL SetProjectState(
        void* context, OpenReverseStringView stateView)
    {
        Impl* manager = Manager(context);
        LoadedExtension* extension = Extension(context);
        if (!OnOwnerThread(manager)) return OPENREVERSE_ERROR_INVALID_STATE;
        if (!extension) return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        if (!HasCapability(extension, OPENREVERSE_CAPABILITY_PROJECT_EXTENSION_STATE))
            return OPENREVERSE_ERROR_PERMISSION_DENIED;
        if (!manager->services.hasProject || !manager->services.hasProject())
            return OPENREVERSE_ERROR_NO_ACTIVE_PROJECT;
        std::string state;
        if (!CopyView(stateView, 256 * 1024, true, state))
            return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        std::string error;
        return manager->services.setExtensionState &&
            manager->services.setExtensionState(extension->manifest.id, state, error)
            ? OPENREVERSE_OK : OPENREVERSE_ERROR_INVALID_ARGUMENT;
    }

    bool RegistrationIdExists(const std::string& id) const
    {
        for (const auto& extension : loaded)
        {
            for (const auto& command : extension->commands) if (command.info.id == id) return true;
            for (const auto& panel : extension->panels) if (panel.info.id == id) return true;
        }
        return false;
    }

    static OpenReverseResult OPENREVERSE_CALL RegisterCommand(
        void* context, const OpenReverseCommandRegistration* registration)
    {
        Impl* manager = Manager(context);
        LoadedExtension* extension = Extension(context);
        if (!OnOwnerThread(manager)) return OPENREVERSE_ERROR_INVALID_STATE;
        if (!extension || !registration ||
            registration->struct_size < sizeof(OpenReverseCommandRegistration) ||
            !registration->execute)
            return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        if (!extension->initializing)
            return OPENREVERSE_ERROR_INVALID_STATE;
        if (!HasCapability(extension, OPENREVERSE_CAPABILITY_UI_COMMAND))
            return OPENREVERSE_ERROR_PERMISSION_DENIED;
        CommandRecord record;
        record.info.extensionId = extension->manifest.id;
        if (!CopyView(registration->command_id, kMaximumRegistrationIdBytes, true, record.info.id) ||
            !ValidRegistrationId(extension->manifest.id, record.info.id) ||
            !CopyView(registration->display_name, kMaximumRegistrationTextBytes, true,
                      record.info.displayName) ||
            !CopyView(registration->category, kMaximumRegistrationTextBytes, true,
                      record.info.category))
            return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        if (manager->RegistrationIdExists(record.info.id) ||
            std::any_of(extension->commands.begin(), extension->commands.end(),
                [&](const CommandRecord& value) { return value.info.id == record.info.id; }) ||
            std::any_of(extension->panels.begin(), extension->panels.end(),
                [&](const PanelRecord& value) { return value.info.id == record.info.id; }))
            return OPENREVERSE_ERROR_DUPLICATE_ID;
        record.execute = registration->execute;
        record.available = registration->is_available;
        record.callbackContext = registration->callback_context;
        extension->commands.push_back(std::move(record));
        return OPENREVERSE_OK;
    }

    static OpenReverseResult OPENREVERSE_CALL RegisterPanel(
        void* context, const OpenReversePanelRegistration* registration)
    {
        Impl* manager = Manager(context);
        LoadedExtension* extension = Extension(context);
        if (!OnOwnerThread(manager)) return OPENREVERSE_ERROR_INVALID_STATE;
        if (!extension || !registration ||
            registration->struct_size < sizeof(OpenReversePanelRegistration) ||
            !registration->render_text)
            return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        if (!extension->initializing)
            return OPENREVERSE_ERROR_INVALID_STATE;
        if (!HasCapability(extension, OPENREVERSE_CAPABILITY_UI_PANEL))
            return OPENREVERSE_ERROR_PERMISSION_DENIED;
        PanelRecord record;
        record.info.extensionId = extension->manifest.id;
        if (!CopyView(registration->panel_id, kMaximumRegistrationIdBytes, true, record.info.id) ||
            !ValidRegistrationId(extension->manifest.id, record.info.id) ||
            !CopyView(registration->title, kMaximumRegistrationTextBytes, true, record.info.title))
            return OPENREVERSE_ERROR_INVALID_ARGUMENT;
        if (manager->RegistrationIdExists(record.info.id) ||
            std::any_of(extension->commands.begin(), extension->commands.end(),
                [&](const CommandRecord& value) { return value.info.id == record.info.id; }) ||
            std::any_of(extension->panels.begin(), extension->panels.end(),
                [&](const PanelRecord& value) { return value.info.id == record.info.id; }))
            return OPENREVERSE_ERROR_DUPLICATE_ID;
        record.info.visible = registration->default_visible != 0;
        record.render = registration->render_text;
        record.callbackContext = registration->callback_context;
        extension->panels.push_back(std::move(record));
        return OPENREVERSE_OK;
    }

    void BuildHostApi(LoadedExtension& extension)
    {
        extension.hostContext = {this, &extension};
        extension.hostApi.struct_size = sizeof(OpenReverseHostApi);
        extension.hostApi.api_version = OPENREVERSE_EXTENSION_API_VERSION;
        extension.hostApi.host_version_major = hostVersion.major;
        extension.hostApi.host_version_minor = hostVersion.minor;
        extension.hostApi.host_version_patch = hostVersion.patch;
        extension.hostApi.granted_capabilities = extension.manifest.capabilities;
        extension.hostApi.host_context = &extension.hostContext;
        extension.hostApi.get_current_target = GetCurrentTarget;
        extension.hostApi.copy_target_text = CopyTargetText;
        extension.hostApi.get_function_count = GetFunctionCount;
        extension.hostApi.get_function = GetFunction;
        extension.hostApi.copy_function_name = CopyFunctionName;
        extension.hostApi.navigate_to_address = NavigateToAddress;
        extension.hostApi.get_project_state = GetProjectState;
        extension.hostApi.set_project_state = SetProjectState;
        extension.hostApi.register_command = RegisterCommand;
        extension.hostApi.register_panel = RegisterPanel;
    }

    void AddDiagnostic(ExtensionDiagnosticKind kind, const ExtensionManifest* manifest,
                       const std::filesystem::path& path, const std::string& message)
    {
        diagnostics.push_back({kind, manifest ? manifest->id : std::string{}, path, message});
    }

    bool Load(const ExtensionManifest& manifest)
    {
        try
        {
        if (manifest.apiVersion != OPENREVERSE_EXTENSION_API_VERSION)
        {
            AddDiagnostic(ExtensionDiagnosticKind::IncompatibleApi, &manifest, manifest.manifestPath,
                "Extension API version is not supported by this host");
            return false;
        }
        if (CompareSemanticVersions(hostVersion, manifest.minimumOpenReverseVersion) < 0)
        {
            AddDiagnostic(ExtensionDiagnosticKind::IncompatibleHost, &manifest, manifest.manifestPath,
                "Extension requires a newer OpenReverse version");
            return false;
        }
        const uint64_t unsupported = manifest.capabilities & ~ExtensionManager::SupportedCapabilities();
        if (unsupported != 0)
        {
            AddDiagnostic(ExtensionDiagnosticKind::UnsupportedCapability, &manifest,
                manifest.manifestPath, "Extension requests a capability not implemented by this host");
            return false;
        }
        if (!std::filesystem::is_regular_file(manifest.modulePath))
        {
            AddDiagnostic(ExtensionDiagnosticKind::MissingModule, &manifest, manifest.modulePath,
                "Extension DLL is missing");
            return false;
        }
        const std::filesystem::path canonicalModule = std::filesystem::canonical(manifest.modulePath);
        const std::filesystem::path canonicalDirectory =
            std::filesystem::canonical(manifest.extensionDirectory);
        if (!SameDirectory(canonicalModule.parent_path(), canonicalDirectory))
        {
            AddDiagnostic(ExtensionDiagnosticKind::LoadFailure, &manifest, manifest.modulePath,
                "Extension DLL resolves outside its manifest directory");
            return false;
        }
        HMODULE module = LoadLibraryExW(canonicalModule.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module)
        {
            AddDiagnostic(ExtensionDiagnosticKind::LoadFailure, &manifest, canonicalModule,
                WindowsError("LoadLibraryExW", GetLastError()));
            return false;
        }
        ModuleGuard moduleGuard{module};
        auto entrypoint = reinterpret_cast<OpenReverseGetDescriptorFunction>(
            GetProcAddress(module, OPENREVERSE_EXTENSION_ENTRYPOINT_NAME));
        if (!entrypoint)
        {
            AddDiagnostic(ExtensionDiagnosticKind::MissingEntrypoint, &manifest, canonicalModule,
                "Extension DLL does not export " OPENREVERSE_EXTENSION_ENTRYPOINT_NAME);
            return false;
        }

        auto extension = std::make_unique<LoadedExtension>();
        extension->manifest = manifest;
        extension->module = module;
        extension->descriptor.struct_size = sizeof(OpenReverseExtensionDescriptor);
        OpenReverseResult descriptorResult = OPENREVERSE_ERROR_INTERNAL;
        try
        {
            descriptorResult = entrypoint(OPENREVERSE_EXTENSION_API_VERSION,
                                          &extension->descriptor);
        }
        catch (...)
        {
            descriptorResult = OPENREVERSE_ERROR_INTERNAL;
        }
        const auto& descriptor = extension->descriptor;
        const bool descriptorValid = descriptorResult == OPENREVERSE_OK &&
            descriptor.struct_size >= sizeof(OpenReverseExtensionDescriptor) &&
            descriptor.api_version == OPENREVERSE_EXTENSION_API_VERSION &&
            descriptor.extension_version_major == manifest.version.major &&
            descriptor.extension_version_minor == manifest.version.minor &&
            descriptor.extension_version_patch == manifest.version.patch &&
            descriptor.requested_capabilities == manifest.capabilities && descriptor.initialize &&
            descriptor.shutdown;
        if (!descriptorValid)
        {
            AddDiagnostic(ExtensionDiagnosticKind::InvalidDescriptor, &manifest, canonicalModule,
                "Extension descriptor does not match its manifest or ABI v1 contract");
            return false;
        }
        BuildHostApi(*extension);
        extension->initializing = true;
        OpenReverseResult initializeResult = OPENREVERSE_ERROR_INTERNAL;
        try
        {
            initializeResult = descriptor.initialize(&extension->hostApi,
                                                      &extension->extensionContext);
        }
        catch (...)
        {
            initializeResult = OPENREVERSE_ERROR_INTERNAL;
        }
        extension->initializing = false;
        if (initializeResult != OPENREVERSE_OK)
        {
            if (extension->extensionContext)
            {
                try { descriptor.shutdown(extension->extensionContext); } catch (...) {}
            }
            AddDiagnostic(ExtensionDiagnosticKind::InitializationFailure, &manifest,
                canonicalModule, "Extension initialization returned error " +
                std::to_string(static_cast<uint32_t>(initializeResult)));
            return false;
        }
        loaded.push_back(std::move(extension));
        moduleGuard.handle = nullptr;
        AddDiagnostic(ExtensionDiagnosticKind::Loaded, &manifest, canonicalModule,
                      "Extension loaded");
        return true;
        }
        catch (const std::exception& exception)
        {
            AddDiagnostic(ExtensionDiagnosticKind::LoadFailure, &manifest, manifest.modulePath,
                std::string("Extension loading failed safely: ") + exception.what());
            return false;
        }
    }

    template<typename Callback, typename Event>
    void Notify(Callback OpenReverseExtensionDescriptor::*member, const Event& event,
                const char* eventName)
    {
        if (shuttingDown) return;
        for (const auto& extension : loaded)
        {
            const Callback callback = extension->descriptor.*member;
            if (!callback) continue;
            OpenReverseResult result = OPENREVERSE_ERROR_INTERNAL;
            try { result = callback(extension->extensionContext, &event); } catch (...) {}
            if (result != OPENREVERSE_OK)
                AddDiagnostic(ExtensionDiagnosticKind::CallbackFailure, &extension->manifest,
                    extension->manifest.modulePath, std::string(eventName) +
                    " callback returned error " + std::to_string(static_cast<uint32_t>(result)));
        }
    }
};

ExtensionManager::ExtensionManager() : impl_(std::make_unique<Impl>()) {}

ExtensionManager::~ExtensionManager()
{
    Shutdown();
}

void ExtensionManager::Configure(ExtensionHostServices services, SemanticVersion hostVersion)
{
    if (impl_->discoveryStarted) return;
    impl_->services = std::move(services);
    impl_->hostVersion = hostVersion;
    impl_->ownerThread = std::this_thread::get_id();
    impl_->configured = true;
}

bool ExtensionManager::DiscoverAndLoad(const std::filesystem::path& extensionRoot)
{
    if (!impl_->configured || impl_->discoveryStarted || impl_->shuttingDown) return false;
    impl_->discoveryStarted = true;
    std::string discoveryError;
    const auto manifests = DiscoverExtensionManifests(extensionRoot, discoveryError);
    if (!discoveryError.empty())
    {
        impl_->AddDiagnostic(ExtensionDiagnosticKind::DiscoveryError, nullptr,
                             extensionRoot, discoveryError);
        return false;
    }
    std::set<std::string> seenIds;
    bool allLoaded = true;
    for (const auto& path : manifests)
    {
        ExtensionManifest manifest;
        std::string error;
        if (!ParseExtensionManifest(path, manifest, error))
        {
            impl_->AddDiagnostic(ExtensionDiagnosticKind::ManifestError, nullptr, path, error);
            allLoaded = false;
            continue;
        }
        if (!seenIds.insert(manifest.id).second)
        {
            impl_->AddDiagnostic(ExtensionDiagnosticKind::DuplicateId, &manifest, path,
                                 "Duplicate extension ID");
            allLoaded = false;
            continue;
        }
        if (!impl_->Load(manifest)) allLoaded = false;
    }
    return allLoaded;
}

void ExtensionManager::Shutdown()
{
    if (!impl_ || impl_->shuttingDown) return;
    impl_->shuttingDown = true;
    for (auto iterator = impl_->loaded.rbegin(); iterator != impl_->loaded.rend(); ++iterator)
    {
        auto& extension = **iterator;
        try { extension.descriptor.shutdown(extension.extensionContext); } catch (...) {}
        extension.commands.clear();
        extension.panels.clear();
        if (extension.module) FreeLibrary(extension.module);
        extension.module = nullptr;
    }
    impl_->loaded.clear();
}

std::vector<LoadedExtensionInfo> ExtensionManager::LoadedExtensions() const
{
    std::vector<LoadedExtensionInfo> result;
    for (const auto& extension : impl_->loaded)
        result.push_back({extension->manifest.id, extension->manifest.name,
                          extension->manifest.version, extension->manifest.capabilities});
    return result;
}

std::vector<ExtensionCommandInfo> ExtensionManager::Commands() const
{
    std::vector<ExtensionCommandInfo> result;
    for (const auto& extension : impl_->loaded)
        for (const auto& command : extension->commands) result.push_back(command.info);
    return result;
}

std::vector<ExtensionPanelInfo> ExtensionManager::Panels() const
{
    std::vector<ExtensionPanelInfo> result;
    for (const auto& extension : impl_->loaded)
        for (const auto& panel : extension->panels) result.push_back(panel.info);
    return result;
}

const std::vector<ExtensionDiagnostic>& ExtensionManager::Diagnostics() const
{
    return impl_->diagnostics;
}

OpenReverseResult ExtensionManager::IsCommandAvailable(const std::string& commandId,
                                                       bool& available,
                                                       std::string& error) const
{
    available = false;
    error.clear();
    for (const auto& extension : impl_->loaded)
    {
        for (const auto& command : extension->commands)
        {
            if (command.info.id != commandId) continue;
            if (!command.available)
            {
                available = true;
                return OPENREVERSE_OK;
            }
            uint32_t value = 0;
            OpenReverseResult result = OPENREVERSE_ERROR_INTERNAL;
            try { result = command.available(command.callbackContext, &value); } catch (...) {}
            if (result != OPENREVERSE_OK)
                error = "Extension command availability callback failed";
            available = result == OPENREVERSE_OK && value != 0;
            return result;
        }
    }
    error = "Extension command was not found";
    return OPENREVERSE_ERROR_NOT_FOUND;
}

OpenReverseResult ExtensionManager::ExecuteCommand(const std::string& commandId, std::string& error)
{
    error.clear();
    bool available = false;
    const OpenReverseResult availability = IsCommandAvailable(commandId, available, error);
    if (availability != OPENREVERSE_OK) return availability;
    if (!available)
    {
        error = "Extension command is not currently available";
        return OPENREVERSE_ERROR_INVALID_STATE;
    }
    for (const auto& extension : impl_->loaded)
    {
        for (const auto& command : extension->commands)
        {
            if (command.info.id != commandId) continue;
            OpenReverseResult result = OPENREVERSE_ERROR_INTERNAL;
            try { result = command.execute(command.callbackContext); } catch (...) {}
            if (result != OPENREVERSE_OK)
            {
                error = "Extension command callback returned error " +
                    std::to_string(static_cast<uint32_t>(result));
                impl_->AddDiagnostic(ExtensionDiagnosticKind::CallbackFailure,
                    &extension->manifest, extension->manifest.modulePath, error);
            }
            return result;
        }
    }
    return OPENREVERSE_ERROR_NOT_FOUND;
}

OpenReverseResult ExtensionManager::RenderPanelText(const std::string& panelId,
                                                    std::string& text,
                                                    std::string& error) const
{
    text.clear();
    error.clear();
    for (const auto& extension : impl_->loaded)
    {
        for (const auto& panel : extension->panels)
        {
            if (panel.info.id != panelId) continue;
            uint32_t required = 0;
            OpenReverseResult result = OPENREVERSE_ERROR_INTERNAL;
            try { result = panel.render(panel.callbackContext, nullptr, 0, &required); } catch (...) {}
            if (result != OPENREVERSE_ERROR_BUFFER_TOO_SMALL && result != OPENREVERSE_OK)
            {
                error = "Extension panel sizing callback failed";
                return result;
            }
            if (required == 0 || required > kMaximumCallbackTextBytes)
            {
                error = "Extension panel text exceeds the 64 KiB host limit";
                return OPENREVERSE_ERROR_INVALID_ARGUMENT;
            }
            std::vector<char> buffer(required, '\0');
            try { result = panel.render(panel.callbackContext, buffer.data(), required, &required); }
            catch (...) { result = OPENREVERSE_ERROR_INTERNAL; }
            if (result != OPENREVERSE_OK || required == 0 || required > buffer.size() ||
                buffer[required - 1] != '\0')
            {
                error = "Extension panel render callback returned invalid text";
                return result == OPENREVERSE_OK ? OPENREVERSE_ERROR_INVALID_ARGUMENT : result;
            }
            text.assign(buffer.data(), required - 1);
            if (!IsValidUtf8(text))
            {
                text.clear();
                error = "Extension panel returned invalid UTF-8";
                return OPENREVERSE_ERROR_INVALID_ARGUMENT;
            }
            return OPENREVERSE_OK;
        }
    }
    error = "Extension panel was not found";
    return OPENREVERSE_ERROR_NOT_FOUND;
}

bool ExtensionManager::SetPanelVisible(const std::string& panelId, bool visible)
{
    for (const auto& extension : impl_->loaded)
        for (auto& panel : extension->panels)
            if (panel.info.id == panelId) { panel.info.visible = visible; return true; }
    return false;
}

void ExtensionManager::NotifySessionChanged(uint64_t generation, bool hasActiveTarget)
{
    OpenReverseSessionEvent event{sizeof(OpenReverseSessionEvent), hasActiveTarget ? 1u : 0u,
                                  generation};
    impl_->Notify(&OpenReverseExtensionDescriptor::session_changed, event, "Session changed");
}

void ExtensionManager::NotifyProjectOpened()
{
    OpenReverseProjectEvent event{sizeof(OpenReverseProjectEvent), 1u, 0};
    impl_->Notify(&OpenReverseExtensionDescriptor::project_opened, event, "Project opened");
}

void ExtensionManager::NotifyProjectClosed()
{
    OpenReverseProjectEvent event{sizeof(OpenReverseProjectEvent), 0u, 0};
    impl_->Notify(&OpenReverseExtensionDescriptor::project_closed, event, "Project closed");
}

std::filesystem::path ExtensionManager::DefaultExtensionRoot()
{
    std::vector<wchar_t> path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) return {};
    return std::filesystem::path(std::wstring(path.data(), length)).parent_path() / "extensions";
}

uint64_t ExtensionManager::SupportedCapabilities()
{
    return OPENREVERSE_CAPABILITY_ANALYSIS_READ |
        OPENREVERSE_CAPABILITY_PROJECT_READ |
        OPENREVERSE_CAPABILITY_PROJECT_EXTENSION_STATE |
        OPENREVERSE_CAPABILITY_NAVIGATION |
        OPENREVERSE_CAPABILITY_UI_PANEL |
        OPENREVERSE_CAPABILITY_UI_COMMAND;
}

const char* ExtensionDiagnosticKindName(ExtensionDiagnosticKind kind)
{
    switch (kind)
    {
    case ExtensionDiagnosticKind::Loaded: return "Loaded";
    case ExtensionDiagnosticKind::DiscoveryError: return "DiscoveryError";
    case ExtensionDiagnosticKind::ManifestError: return "ManifestError";
    case ExtensionDiagnosticKind::DuplicateId: return "DuplicateId";
    case ExtensionDiagnosticKind::IncompatibleApi: return "IncompatibleApi";
    case ExtensionDiagnosticKind::IncompatibleHost: return "IncompatibleHost";
    case ExtensionDiagnosticKind::UnsupportedCapability: return "UnsupportedCapability";
    case ExtensionDiagnosticKind::MissingModule: return "MissingModule";
    case ExtensionDiagnosticKind::LoadFailure: return "LoadFailure";
    case ExtensionDiagnosticKind::MissingEntrypoint: return "MissingEntrypoint";
    case ExtensionDiagnosticKind::InvalidDescriptor: return "InvalidDescriptor";
    case ExtensionDiagnosticKind::InitializationFailure: return "InitializationFailure";
    default: return "CallbackFailure";
    }
}

} // namespace openreverse::extensions
