#include "module_catalog.h"
#include "utils/helpers.h"

#include <psapi.h>

#include <algorithm>
#include <vector>

namespace openreverse {

void ModuleCatalog::RefreshModules(HANDLE processHandle)
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

const ModuleInfo* ModuleCatalog::FindModuleByAddress(uint64_t address) const
{
    for (const auto& m : modules_)
    {
        if (address >= m.baseAddress && address - m.baseAddress < m.size)
            return &m;
    }
    return nullptr;
}

} // namespace openreverse
