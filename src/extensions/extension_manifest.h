#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace openreverse::extensions {

struct SemanticVersion {
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t patch = 0;
};

struct ExtensionManifest {
    std::string id;
    std::string name;
    SemanticVersion version;
    uint32_t apiVersion = 0;
    SemanticVersion minimumOpenReverseVersion;
    std::string author;
    std::string description;
    std::vector<std::string> capabilityNames;
    uint64_t capabilities = 0;
    std::string entrypoint;
    std::filesystem::path manifestPath;
    std::filesystem::path extensionDirectory;
    std::filesystem::path modulePath;
};

bool ParseSemanticVersion(const std::string& text, SemanticVersion& version);
int CompareSemanticVersions(const SemanticVersion& left, const SemanticVersion& right);
bool IsValidExtensionId(const std::string& id);
bool ParseExtensionManifest(const std::filesystem::path& path, ExtensionManifest& manifest,
                            std::string& error);
std::vector<std::filesystem::path> DiscoverExtensionManifests(
    const std::filesystem::path& extensionRoot, std::string& error);
const char* CapabilityName(uint64_t capability);

} // namespace openreverse::extensions
