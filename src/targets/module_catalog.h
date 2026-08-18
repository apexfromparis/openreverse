#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace openreverse {

struct ModuleInfo {
    std::string name;
    std::string path;
    uint64_t    baseAddress;
    uint64_t    size;
};

class ModuleCatalog {
public:
    void RefreshModules(HANDLE processHandle);

    const std::vector<ModuleInfo>& GetModules() const { return modules_; }

    const ModuleInfo* FindModuleByAddress(uint64_t address) const;

    void Clear() { modules_.clear(); }
    void AddModule(const std::string& name, uint64_t baseAddress, uint64_t size, const std::string& path = "")
    {
        ModuleInfo mi;
        mi.name = name;
        mi.baseAddress = baseAddress;
        mi.size = size;
        mi.path = path;
        modules_.push_back(mi);
    }

private:
    std::vector<ModuleInfo> modules_;
};

} // namespace openreverse
