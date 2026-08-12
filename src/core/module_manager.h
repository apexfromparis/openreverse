#pragma once
// OpenReverse - Core: Module Manager
// Enumerate loaded modules and their exports

#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <cstdint>

namespace openreverse {

struct ModuleInfo {
    std::string name;
    std::string path;
    uint64_t    baseAddress;
    uint64_t    size;
};

struct ExportInfo {
    std::string name;
    uint64_t    address;
    uint16_t    ordinal;
};

class ModuleManager {
public:
    // Refresh module list for process
    void RefreshModules(HANDLE processHandle);

    // Get cached modules
    const std::vector<ModuleInfo>& GetModules() const { return modules_; }

    // Get exports for a specific module
    std::vector<ExportInfo> GetExports(HANDLE processHandle, uint64_t moduleBase);

    // Find module by name
    const ModuleInfo* FindModule(const std::string& name) const;

    // Find module containing address
    const ModuleInfo* FindModuleByAddress(uint64_t address) const;

    // Manual offline module management
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
