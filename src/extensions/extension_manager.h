#pragma once

#include "extensions/extension_manifest.h"

#include <openreverse/extension.h>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace openreverse::extensions {

struct ExtensionTargetSnapshot {
    std::string name;
    std::string path;
    std::string sha256;
    uint32_t architecture = OPENREVERSE_ARCHITECTURE_UNKNOWN;
    uint64_t imageBase = 0;
    uint64_t imageSize = 0;
    uint64_t currentAddress = 0;
    uint64_t analysisRevision = 0;
    uint32_t peTimestamp = 0;
    uint32_t functionCount = 0;
};

struct ExtensionFunctionSnapshot {
    std::string name;
    uint64_t address = 0;
    uint64_t rva = 0;
    uint64_t size = 0;
    uint32_t instructionCount = 0;
    uint32_t basicBlockCount = 0;
    uint32_t directCallCount = 0;
    bool boundaryKnown = false;
};

struct ExtensionHostServices {
    std::function<bool(ExtensionTargetSnapshot&)> currentTarget;
    std::function<bool(uint32_t, ExtensionFunctionSnapshot&)> functionByIndex;
    std::function<bool(uint64_t)> navigateToAddress;
    std::function<bool()> hasProject;
    std::function<std::string()> projectPath;
    std::function<bool(const std::string&, std::string&)> getExtensionState;
    std::function<bool(const std::string&, const std::string&, std::string&)> setExtensionState;
};

enum class ExtensionDiagnosticKind {
    Loaded,
    DiscoveryError,
    ManifestError,
    DuplicateId,
    IncompatibleApi,
    IncompatibleHost,
    UnsupportedCapability,
    MissingModule,
    LoadFailure,
    MissingEntrypoint,
    InvalidDescriptor,
    InitializationFailure,
    CallbackFailure
};

struct ExtensionDiagnostic {
    ExtensionDiagnosticKind kind = ExtensionDiagnosticKind::ManifestError;
    std::string extensionId;
    std::filesystem::path path;
    std::string message;
};

struct LoadedExtensionInfo {
    std::string id;
    std::string name;
    SemanticVersion version;
    uint64_t capabilities = 0;
};

struct ExtensionCommandInfo {
    std::string extensionId;
    std::string id;
    std::string displayName;
    std::string category;
};

struct ExtensionPanelInfo {
    std::string extensionId;
    std::string id;
    std::string title;
    bool visible = false;
};

class ExtensionManager {
public:
    ExtensionManager();
    ~ExtensionManager();
    ExtensionManager(const ExtensionManager&) = delete;
    ExtensionManager& operator=(const ExtensionManager&) = delete;

    void Configure(ExtensionHostServices services, SemanticVersion hostVersion);
    bool DiscoverAndLoad(const std::filesystem::path& extensionRoot);
    void Shutdown();

    std::vector<LoadedExtensionInfo> LoadedExtensions() const;
    std::vector<ExtensionCommandInfo> Commands() const;
    std::vector<ExtensionPanelInfo> Panels() const;
    const std::vector<ExtensionDiagnostic>& Diagnostics() const;

    OpenReverseResult IsCommandAvailable(const std::string& commandId, bool& available,
                                         std::string& error) const;
    OpenReverseResult ExecuteCommand(const std::string& commandId, std::string& error);
    OpenReverseResult RenderPanelText(const std::string& panelId, std::string& text,
                                      std::string& error) const;
    bool SetPanelVisible(const std::string& panelId, bool visible);

    void NotifySessionChanged(uint64_t generation, bool hasActiveTarget);
    void NotifyProjectOpened();
    void NotifyProjectClosed();

    static std::filesystem::path DefaultExtensionRoot();
    static uint64_t SupportedCapabilities();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

const char* ExtensionDiagnosticKindName(ExtensionDiagnosticKind kind);

} // namespace openreverse::extensions
