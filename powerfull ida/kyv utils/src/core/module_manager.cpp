// ============================================================================
// KYV - Core: Module Manager Implementation
// ============================================================================

#include "module_manager.h"
#include <algorithm>

namespace kyv {

void ModuleManager::RefreshModules(HANDLE processHandle)
{
    modules_.clear();
    if (!processHandle)
        return;

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModulesEx(processHandle, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
    {
        size_t count = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < count; ++i)
        {
            ModuleInfo mod;
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
            MODULEINFO mi;
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

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(processHandle, (LPCVOID)moduleBase, &dosHeader, sizeof(dosHeader), &bytesRead))
        return exports;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return exports;

    // Read NT headers
    IMAGE_NT_HEADERS64 ntHeaders;
    uint64_t ntAddr = moduleBase + dosHeader.e_lfanew;
    if (!ReadProcessMemory(processHandle, (LPCVOID)ntAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead))
        return exports;

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        return exports;

    // Get export directory
    DWORD exportDirRVA = 0;
    DWORD exportDirSize = 0;

    if (ntHeaders.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        if (ntHeaders.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            exportDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportDirSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
    }
    else
    {
        // 32-bit
        IMAGE_NT_HEADERS32 ntHeaders32;
        ReadProcessMemory(processHandle, (LPCVOID)ntAddr, &ntHeaders32, sizeof(ntHeaders32), &bytesRead);
        if (ntHeaders32.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            exportDirRVA = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportDirSize = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
    }

    if (exportDirRVA == 0)
        return exports;

    // Read export directory
    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadProcessMemory(processHandle, (LPCVOID)(moduleBase + exportDirRVA), &exportDir, sizeof(exportDir), &bytesRead))
        return exports;

    // Read function addresses, names, and ordinals
    std::vector<DWORD> functions(exportDir.NumberOfFunctions);
    std::vector<DWORD> names(exportDir.NumberOfNames);
    std::vector<WORD>  ordinals(exportDir.NumberOfNames);

    ReadProcessMemory(processHandle, (LPCVOID)(moduleBase + exportDir.AddressOfFunctions),
        functions.data(), functions.size() * sizeof(DWORD), &bytesRead);
    ReadProcessMemory(processHandle, (LPCVOID)(moduleBase + exportDir.AddressOfNames),
        names.data(), names.size() * sizeof(DWORD), &bytesRead);
    ReadProcessMemory(processHandle, (LPCVOID)(moduleBase + exportDir.AddressOfNameOrdinals),
        ordinals.data(), ordinals.size() * sizeof(WORD), &bytesRead);

    // Build export list
    for (DWORD i = 0; i < exportDir.NumberOfNames && i < 10000; ++i)
    {
        ExportInfo exp;

        // Read name
        char nameBuf[512];
        if (ReadProcessMemory(processHandle, (LPCVOID)(moduleBase + names[i]), nameBuf, sizeof(nameBuf), &bytesRead))
        {
            nameBuf[511] = 0;
            exp.name = nameBuf;
        }

        exp.ordinal = ordinals[i] + (uint16_t)exportDir.Base;

        if (ordinals[i] < functions.size())
            exp.address = moduleBase + functions[ordinals[i]];
        else
            exp.address = 0;

        exports.push_back(exp);
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

} // namespace kyv
