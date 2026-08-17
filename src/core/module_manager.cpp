#include "module_manager.h"
#include "pe_parser.h"
#include "utils/helpers.h"
#include <algorithm>
#include <iterator>
#include <limits>
#include <utility>
#include <vector>

namespace openreverse {

void ModuleManager::RefreshModules(HANDLE processHandle)
{
    modules_.clear();
    if (!processHandle)
        return;

    std::vector<HMODULE> modules(256);
    DWORD cbNeeded = 0;
    if (!EnumProcessModulesEx(processHandle, modules.data(),
                              static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                              &cbNeeded, LIST_MODULES_ALL))
        return;
    if (cbNeeded > modules.size() * sizeof(HMODULE))
    {
        const size_t requested = cbNeeded / sizeof(HMODULE) + 1;
        if (requested > 16384) return;
        modules.resize(requested);
        if (!EnumProcessModulesEx(processHandle, modules.data(),
                                  static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                                  &cbNeeded, LIST_MODULES_ALL))
            return;
    }
    {
        const size_t count = (std::min)(static_cast<size_t>(cbNeeded / sizeof(HMODULE)), modules.size());
        for (size_t i = 0; i < count; ++i)
        {
            ModuleInfo mod{};
            mod.baseAddress = reinterpret_cast<uint64_t>(modules[i]);

            std::vector<wchar_t> nameBuffer(1024, L'\0');
            const DWORD nameLength = GetModuleBaseNameW(processHandle, modules[i],
                nameBuffer.data(), static_cast<DWORD>(nameBuffer.size()));
            if (nameLength != 0 && nameLength < nameBuffer.size())
            {
                nameBuffer[nameLength] = L'\0';
                mod.name = helpers::WideToUtf8(nameBuffer.data());
            }

            std::vector<wchar_t> pathBuffer(1024, L'\0');
            while (pathBuffer.size() <= 32768)
            {
                const DWORD length = GetModuleFileNameExW(processHandle, modules[i],
                    pathBuffer.data(), static_cast<DWORD>(pathBuffer.size()));
                if (length == 0) break;
                if (length < pathBuffer.size() - 1)
                {
                    pathBuffer[length] = L'\0';
                    mod.path = helpers::WideToUtf8(pathBuffer.data());
                    break;
                }
                if (pathBuffer.size() == 32768) break;
                pathBuffer.resize((std::min<size_t>)(pathBuffer.size() * 2, 32768), L'\0');
            }

            MODULEINFO mi{};
            if (GetModuleInformation(processHandle, modules[i], &mi, sizeof(mi)))
            {
                mod.size = mi.SizeOfImage;
            }

            modules_.push_back(mod);
        }
    }

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
        if (address >= m.baseAddress && address - m.baseAddress < m.size)
            return &m;
    }
    return nullptr;
}

} // namespace openreverse
