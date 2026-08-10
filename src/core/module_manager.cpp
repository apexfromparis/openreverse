// ============================================================================
// OpenReverse - Core: Module Manager Implementation
// ============================================================================

#include "module_manager.h"
#include "pe_parser.h"
#include <algorithm>
#include <iterator>
#include <limits>
#include <utility>

namespace openreverse {

void ModuleManager::RefreshModules(HANDLE processHandle)
{
    modules_.clear();
    if (!processHandle)
        return;

    HMODULE hMods[1024]{};
    DWORD cbNeeded = 0;

    if (EnumProcessModulesEx(processHandle, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
    {
        size_t count = (std::min)(static_cast<size_t>(cbNeeded / sizeof(HMODULE)), std::size(hMods));
        for (size_t i = 0; i < count; ++i)
        {
            ModuleInfo mod{};
            mod.baseAddress = (uint64_t)hMods[i];

            // Get module name
            wchar_t modName[MAX_PATH];
            if (GetModuleBaseNameW(processHandle, hMods[i], modName, MAX_PATH))
            {
                char name[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, modName, -1, name, MAX_PATH, nullptr, nullptr);
                mod.name = name;
            }

            // Get module path
            wchar_t modPath[MAX_PATH];
            if (GetModuleFileNameExW(processHandle, hMods[i], modPath, MAX_PATH))
            {
                char path[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, modPath, -1, path, MAX_PATH, nullptr, nullptr);
                mod.path = path;
            }

            // Get module size
            MODULEINFO mi{};
            if (GetModuleInformation(processHandle, hMods[i], &mi, sizeof(mi)))
            {
                mod.size = mi.SizeOfImage;
            }

            modules_.push_back(mod);
        }
    }

    // Sort by base address
    std::sort(modules_.begin(), modules_.end(),
        [](const ModuleInfo& a, const ModuleInfo& b) { return a.baseAddress < b.baseAddress; });
}

std::vector<ExportInfo> ModuleManager::GetExports(HANDLE processHandle, uint64_t moduleBase)
{
    std::vector<ExportInfo> exports;
    if (!processHandle)
        return exports;

    const auto module = std::find_if(modules_.begin(), modules_.end(), [moduleBase](const ModuleInfo& value) {
        return value.baseAddress == moduleBase;
    });
    if (module == modules_.end() || module->size == 0)
        return exports;

    PEParser parser;
    const PEInfo pe = parser.Parse(processHandle, moduleBase, module->size);
    if (!pe.valid)
        return exports;

    exports.reserve((std::min)(pe.exports.size(), static_cast<size_t>(10000)));
    for (const auto& entry : pe.exports)
    {
        if (exports.size() >= 10000 || entry.ordinal > (std::numeric_limits<uint16_t>::max)())
            break;
        ExportInfo exp;
        exp.name = entry.name;
        exp.ordinal = static_cast<uint16_t>(entry.ordinal);
        if (!entry.isForwarder && entry.rva <= (std::numeric_limits<uint64_t>::max)() - moduleBase)
            exp.address = moduleBase + entry.rva;
        exports.push_back(std::move(exp));
    }

    return exports;
}

const ModuleInfo* ModuleManager::FindModule(const std::string& name) const
{
    for (const auto& m : modules_)
    {
        if (_stricmp(m.name.c_str(), name.c_str()) == 0)
            return &m;
    }
    return nullptr;
}

const ModuleInfo* ModuleManager::FindModuleByAddress(uint64_t address) const
{
    for (const auto& m : modules_)
    {
        if (address >= m.baseAddress && address < m.baseAddress + m.size)
            return &m;
    }
    return nullptr;
}

} // namespace openreverse
