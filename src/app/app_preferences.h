#pragma once

#include <string>

namespace openreverse {

struct AppPreferences {
    bool onboardingSeen = false;

    static AppPreferences Load();
    bool Save() const;
    static std::string PreferencesFilePath();
};

} // namespace openreverse
