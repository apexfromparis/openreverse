#include "app_preferences.h"

#include <windows.h>
#include <shlobj.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <system_error>

namespace openreverse {

namespace {

std::filesystem::path GetOpenReverseDataDirectory()
{
    PWSTR localAppData = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &localAppData)) && localAppData)
    {
        std::filesystem::path dir = std::filesystem::path(localAppData) / "OpenReverse";
        CoTaskMemFree(localAppData);
        return dir;
    }

    std::vector<wchar_t> envBuf(32768, L'\0');
    const DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", envBuf.data(), static_cast<DWORD>(envBuf.size()));
    if (len > 0 && len < envBuf.size())
    {
        return std::filesystem::path(std::wstring(envBuf.data(), len)) / "OpenReverse";
    }

    return std::filesystem::temp_directory_path() / "OpenReverse";
}

} // namespace

std::string AppPreferences::PreferencesFilePath()
{
    return (GetOpenReverseDataDirectory() / "preferences.json").string();
}

AppPreferences AppPreferences::Load()
{
    AppPreferences prefs;
    const std::filesystem::path path = GetOpenReverseDataDirectory() / "preferences.json";

    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec))
    {
        return prefs;
    }

    try
    {
        std::ifstream file(path);
        if (!file.is_open()) return prefs;

        nlohmann::json root = nlohmann::json::parse(file, nullptr, false);
        if (root.is_discarded() || !root.is_object()) return prefs;

        if (root.contains("onboarding_seen") && root["onboarding_seen"].is_boolean())
        {
            prefs.onboardingSeen = root["onboarding_seen"].get<bool>();
        }
    }
    catch (...)
    {
        // Fail-open with default preferences if corrupted
    }

    return prefs;
}

bool AppPreferences::Save() const
{
    try
    {
        const std::filesystem::path dir = GetOpenReverseDataDirectory();
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);

        const std::filesystem::path path = dir / "preferences.json";
        nlohmann::json root = {
            {"onboarding_seen", onboardingSeen}
        };

        std::ofstream file(path);
        if (!file.is_open()) return false;

        file << root.dump(2);
        return file.good();
    }
    catch (...)
    {
        return false;
    }
}

} // namespace openreverse
