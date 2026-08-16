#include "extension_manifest.h"

#include <openreverse/extension.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <fstream>
#include <limits>
#include <map>
#include <set>

namespace openreverse::extensions {

namespace {

using json = nlohmann::json;

constexpr uintmax_t kMaximumManifestBytes = 64 * 1024;
constexpr size_t kMaximumIdLength = 128;
constexpr size_t kMaximumNameLength = 256;
constexpr size_t kMaximumDescriptionLength = 4096;
constexpr size_t kMaximumCapabilities = 32;

const std::map<std::string, uint64_t>& CapabilityMap()
{
    static const std::map<std::string, uint64_t> capabilities = {
        {"analysis.read", OPENREVERSE_CAPABILITY_ANALYSIS_READ},
        {"project.read", OPENREVERSE_CAPABILITY_PROJECT_READ},
        {"project.extension_state", OPENREVERSE_CAPABILITY_PROJECT_EXTENSION_STATE},
        {"navigation", OPENREVERSE_CAPABILITY_NAVIGATION},
        {"ui.panel", OPENREVERSE_CAPABILITY_UI_PANEL},
        {"ui.command", OPENREVERSE_CAPABILITY_UI_COMMAND},
        {"ai.action", OPENREVERSE_CAPABILITY_AI_ACTION},
        {"analysis.action", OPENREVERSE_CAPABILITY_ANALYSIS_ACTION},
        {"filesystem", OPENREVERSE_CAPABILITY_FILESYSTEM},
        {"network", OPENREVERSE_CAPABILITY_NETWORK},
        {"process.memory", OPENREVERSE_CAPABILITY_PROCESS_MEMORY},
        {"project.write", OPENREVERSE_CAPABILITY_PROJECT_WRITE}
    };
    return capabilities;
}

bool ReadString(const json& value, const char* key, std::string& output,
                size_t maximumLength, bool required = true)
{
    const auto found = value.find(key);
    if (found == value.end()) return !required;
    if (!found->is_string()) return false;
    output = found->get<std::string>();
    return (!required || !output.empty()) && output.size() <= maximumLength;
}

bool EqualPath(const std::filesystem::path& left, const std::filesystem::path& right)
{
    std::wstring leftText = left.lexically_normal().wstring();
    std::wstring rightText = right.lexically_normal().wstring();
    std::transform(leftText.begin(), leftText.end(), leftText.begin(),
        [](wchar_t value) { return static_cast<wchar_t>(std::towlower(value)); });
    std::transform(rightText.begin(), rightText.end(), rightText.begin(),
        [](wchar_t value) { return static_cast<wchar_t>(std::towlower(value)); });
    return leftText == rightText;
}

} // namespace

bool ParseSemanticVersion(const std::string& text, SemanticVersion& version)
{
    if (text.empty() || text.size() > 32) return false;
    uint64_t components[3]{};
    size_t component = 0;
    size_t start = 0;
    while (component < 3)
    {
        const size_t end = text.find('.', start);
        const size_t length = (end == std::string::npos ? text.size() : end) - start;
        if (length == 0 || length > 10) return false;
        if (length > 1 && text[start] == '0') return false;
        uint64_t parsed = 0;
        for (size_t index = start; index < start + length; ++index)
        {
            const unsigned char character = static_cast<unsigned char>(text[index]);
            if (!std::isdigit(character)) return false;
            parsed = parsed * 10 + static_cast<uint64_t>(character - '0');
            if (parsed > (std::numeric_limits<uint32_t>::max)()) return false;
        }
        components[component++] = parsed;
        if (component == 3 && end != std::string::npos) return false;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (component != 3 || text.find('.', start) != std::string::npos) return false;
    version = {static_cast<uint32_t>(components[0]), static_cast<uint32_t>(components[1]),
               static_cast<uint32_t>(components[2])};
    return true;
}

int CompareSemanticVersions(const SemanticVersion& left, const SemanticVersion& right)
{
    if (left.major != right.major) return left.major < right.major ? -1 : 1;
    if (left.minor != right.minor) return left.minor < right.minor ? -1 : 1;
    if (left.patch != right.patch) return left.patch < right.patch ? -1 : 1;
    return 0;
}

bool IsValidExtensionId(const std::string& id)
{
    if (id.size() < 3 || id.size() > kMaximumIdLength ||
        !std::isalnum(static_cast<unsigned char>(id.front())))
        return false;
    bool previousDot = false;
    for (unsigned char character : id)
    {
        const bool dot = character == '.';
        if (!(std::islower(character) || std::isdigit(character) || dot || character == '-'))
            return false;
        if (dot && previousDot) return false;
        previousDot = dot;
    }
    return !previousDot && id.find('.') != std::string::npos;
}

bool ParseExtensionManifest(const std::filesystem::path& path, ExtensionManifest& manifest,
                            std::string& error)
{
    manifest = {};
    error.clear();
    try
    {
        if (std::filesystem::is_symlink(std::filesystem::symlink_status(path)) ||
            !std::filesystem::is_regular_file(path))
        {
            error = "Extension manifest does not exist or is a symbolic link";
            return false;
        }
        const uintmax_t size = std::filesystem::file_size(path);
        if (size == 0 || size > kMaximumManifestBytes)
        {
            error = "Extension manifest is empty or exceeds 64 KiB";
            return false;
        }
        std::ifstream stream(path, std::ios::binary);
        std::string text(static_cast<size_t>(size), '\0');
        stream.read(text.data(), static_cast<std::streamsize>(text.size()));
        if (!stream || stream.gcount() != static_cast<std::streamsize>(text.size()))
        {
            error = "Extension manifest could not be read completely";
            return false;
        }
        const json root = json::parse(text);
        if (!root.is_object() || root.size() > 16)
        {
            error = "Extension manifest root must be a bounded JSON object";
            return false;
        }
        std::string versionText;
        std::string minimumVersionText;
        if (!ReadString(root, "id", manifest.id, kMaximumIdLength) ||
            !IsValidExtensionId(manifest.id) ||
            !ReadString(root, "name", manifest.name, kMaximumNameLength) ||
            !ReadString(root, "version", versionText, 32) ||
            !ParseSemanticVersion(versionText, manifest.version) ||
            !root.contains("api_version") || !root["api_version"].is_number_unsigned() ||
            !ReadString(root, "minimum_openreverse_version", minimumVersionText, 32) ||
            !ParseSemanticVersion(minimumVersionText, manifest.minimumOpenReverseVersion) ||
            !ReadString(root, "author", manifest.author, kMaximumNameLength) ||
            !ReadString(root, "description", manifest.description, kMaximumDescriptionLength) ||
            !ReadString(root, "entrypoint", manifest.entrypoint, kMaximumNameLength))
        {
            error = "Extension manifest contains invalid identity, version, or entrypoint fields";
            return false;
        }
        const uint64_t apiVersion = root["api_version"].get<uint64_t>();
        if (apiVersion == 0 || apiVersion > (std::numeric_limits<uint32_t>::max)())
        {
            error = "Extension API version is outside the supported integer range";
            return false;
        }
        manifest.apiVersion = static_cast<uint32_t>(apiVersion);
        if (!root.contains("capabilities") || !root["capabilities"].is_array() ||
            root["capabilities"].size() > kMaximumCapabilities)
        {
            error = "Extension capabilities must be a bounded JSON array";
            return false;
        }
        std::set<std::string> uniqueCapabilities;
        for (const auto& value : root["capabilities"])
        {
            if (!value.is_string())
            {
                error = "Extension capability names must be strings";
                return false;
            }
            const std::string name = value.get<std::string>();
            const auto capability = CapabilityMap().find(name);
            if (capability == CapabilityMap().end())
            {
                error = "Unknown extension capability: " + name;
                return false;
            }
            if (!uniqueCapabilities.insert(name).second)
            {
                error = "Duplicate extension capability: " + name;
                return false;
            }
            manifest.capabilityNames.push_back(name);
            manifest.capabilities |= capability->second;
        }

        const std::filesystem::path entrypointPath(manifest.entrypoint);
        std::wstring extension = entrypointPath.extension().wstring();
        std::transform(extension.begin(), extension.end(), extension.begin(),
            [](wchar_t value) { return static_cast<wchar_t>(std::towlower(value)); });
        if (entrypointPath.is_absolute() || entrypointPath.has_parent_path() ||
            entrypointPath.filename() != entrypointPath || extension != L".dll" ||
            manifest.entrypoint.find("..") != std::string::npos)
        {
            error = "Extension entrypoint must be a filename-only DLL path";
            return false;
        }

        manifest.manifestPath = std::filesystem::weakly_canonical(path);
        manifest.extensionDirectory = manifest.manifestPath.parent_path();
        manifest.modulePath = std::filesystem::weakly_canonical(
            manifest.extensionDirectory / entrypointPath);
        if (!EqualPath(manifest.modulePath.parent_path(), manifest.extensionDirectory))
        {
            error = "Extension entrypoint escapes its manifest directory";
            return false;
        }
        return true;
    }
    catch (const std::exception& exception)
    {
        error = std::string("Extension manifest parsing failed: ") + exception.what();
        return false;
    }
}

std::vector<std::filesystem::path> DiscoverExtensionManifests(
    const std::filesystem::path& extensionRoot, std::string& error)
{
    std::vector<std::filesystem::path> manifests;
    error.clear();
    try
    {
        if (!std::filesystem::exists(extensionRoot)) return manifests;
        if (!std::filesystem::is_directory(extensionRoot))
        {
            error = "Configured extension root is not a directory";
            return manifests;
        }
        const auto canonicalRoot = std::filesystem::weakly_canonical(extensionRoot);
        for (const auto& entry : std::filesystem::directory_iterator(extensionRoot))
        {
            if (!entry.is_directory()) continue;
            const auto entryStatus = entry.symlink_status();
            const auto canonicalEntry = std::filesystem::weakly_canonical(entry.path());
            if (std::filesystem::is_symlink(entryStatus) ||
                !EqualPath(canonicalEntry.parent_path(), canonicalRoot))
            {
                error = "Extension discovery rejected a directory that resolves outside the configured root";
                manifests.clear();
                return manifests;
            }
            const auto manifest = canonicalEntry / "manifest.json";
            if (std::filesystem::is_regular_file(manifest))
                manifests.push_back(std::filesystem::absolute(manifest).lexically_normal());
        }
        std::sort(manifests.begin(), manifests.end());
    }
    catch (const std::exception& exception)
    {
        error = std::string("Extension discovery failed: ") + exception.what();
    }
    return manifests;
}

const char* CapabilityName(uint64_t capability)
{
    for (const auto& [name, value] : CapabilityMap())
        if (value == capability) return name.c_str();
    return "unknown";
}

} // namespace openreverse::extensions
