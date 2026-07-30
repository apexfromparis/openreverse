// ============================================================================
// KYV - Core: PE Parser Implementation
// ============================================================================

#include "pe_parser.h"
#include <cstring>

namespace kyv {

PEInfo PEParser::Parse(HANDLE processHandle, uint64_t baseAddress)
{
    PEInfo info;
    info.valid = false;
    SIZE_T bytesRead;

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(processHandle, (LPCVOID)baseAddress, &dosHeader, sizeof(dosHeader), &bytesRead))
        return info;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return info;

    info.dosMagic = dosHeader.e_magic;
    info.peOffset = dosHeader.e_lfanew;

    // Read NT signature + file header
    uint64_t ntAddr = baseAddress + dosHeader.e_lfanew;
    DWORD ntSig;
    if (!ReadProcessMemory(processHandle, (LPCVOID)ntAddr, &ntSig, sizeof(ntSig), &bytesRead))
        return info;

    if (ntSig != IMAGE_NT_SIGNATURE)
        return info;

    // Read file header
    IMAGE_FILE_HEADER fileHeader;
    if (!ReadProcessMemory(processHandle, (LPCVOID)(ntAddr + 4), &fileHeader, sizeof(fileHeader), &bytesRead))
        return info;

    info.machine = fileHeader.Machine;
    info.numberOfSections = fileHeader.NumberOfSections;
    info.timestamp = fileHeader.TimeDateStamp;

    // Determine if 64-bit from optional header magic
    uint16_t optMagic;
    uint64_t optAddr = ntAddr + 4 + sizeof(IMAGE_FILE_HEADER);
    ReadProcessMemory(processHandle, (LPCVOID)optAddr, &optMagic, sizeof(optMagic), &bytesRead);

    info.is64bit = (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    uint32_t importDirRVA = 0;
    uint32_t exportDirRVA = 0;

    if (info.is64bit)
    {
        IMAGE_OPTIONAL_HEADER64 optHeader;
        ReadProcessMemory(processHandle, (LPCVOID)optAddr, &optHeader, sizeof(optHeader), &bytesRead);

        info.sizeOfImage = optHeader.SizeOfImage;
        info.entryPoint = optHeader.AddressOfEntryPoint;
        info.imageBase = optHeader.ImageBase;

        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            importDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
            exportDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }
    else
    {
        IMAGE_OPTIONAL_HEADER32 optHeader;
        ReadProcessMemory(processHandle, (LPCVOID)optAddr, &optHeader, sizeof(optHeader), &bytesRead);

        info.sizeOfImage = optHeader.SizeOfImage;
        info.entryPoint = optHeader.AddressOfEntryPoint;
        info.imageBase = optHeader.ImageBase;

        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            importDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
            exportDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }

    // Parse sections
    uint64_t sectionAddr = optAddr + (info.is64bit ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32));
    ParseSections(processHandle, sectionAddr, info.numberOfSections, info.is64bit, info);

    // Parse imports
    if (importDirRVA != 0)
        ParseImports(processHandle, baseAddress, importDirRVA, info.is64bit, info);

    // Parse exports
    if (exportDirRVA != 0)
        ParseExports(processHandle, baseAddress, exportDirRVA, info.is64bit, info);

    info.valid = true;
    return info;
}

void PEParser::ParseSections(HANDLE processHandle, uint64_t sectionAddr,
                               uint16_t numSections, bool is64bit, PEInfo& info)
{
    for (uint16_t i = 0; i < numSections && i < 64; ++i)
    {
        IMAGE_SECTION_HEADER sec;
        SIZE_T bytesRead;

        if (!ReadProcessMemory(processHandle, (LPCVOID)(sectionAddr + i * sizeof(IMAGE_SECTION_HEADER)),
                               &sec, sizeof(sec), &bytesRead))
            break;

        PESectionInfo si;
        memset(si.name, 0, sizeof(si.name));
        memcpy(si.name, sec.Name, 8);
        si.virtualAddress = sec.VirtualAddress;
        si.virtualSize = sec.Misc.VirtualSize;
        si.rawDataOffset = sec.PointerToRawData;
        si.rawDataSize = sec.SizeOfRawData;
        si.characteristics = sec.Characteristics;

        info.sections.push_back(si);
    }
}

void PEParser::ParseImports(HANDLE processHandle, uint64_t baseAddress,
                              uint32_t importDirRVA, bool is64bit, PEInfo& info)
{
    uint64_t importAddr = baseAddress + importDirRVA;
    SIZE_T bytesRead;

    for (int i = 0; i < 256; ++i) // max 256 imports
    {
        IMAGE_IMPORT_DESCRIPTOR desc;
        if (!ReadProcessMemory(processHandle, (LPCVOID)(importAddr + i * sizeof(desc)),
                               &desc, sizeof(desc), &bytesRead))
            break;

        if (desc.Name == 0)
            break;

        PEImportEntry entry;

        // Read DLL name
        char dllName[256];
        if (ReadProcessMemory(processHandle, (LPCVOID)(baseAddress + desc.Name),
                               dllName, sizeof(dllName), &bytesRead))
        {
            dllName[255] = 0;
            entry.dllName = dllName;
        }

        // Read import names (limited to first 100 per DLL)
        uint64_t thunkAddr = baseAddress + (desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk);
        for (int j = 0; j < 100; ++j)
        {
            uint64_t thunkValue = 0;
            size_t thunkSize = is64bit ? 8 : 4;

            if (!ReadProcessMemory(processHandle, (LPCVOID)(thunkAddr + j * thunkSize),
                                   &thunkValue, thunkSize, &bytesRead))
                break;

            if (thunkValue == 0)
                break;

            // Check if import by ordinal
            bool byOrdinal = is64bit
                ? (thunkValue & 0x8000000000000000ULL) != 0
                : (thunkValue & 0x80000000ULL) != 0;

            if (byOrdinal)
            {
                uint16_t ord = (uint16_t)(thunkValue & 0xFFFF);
                entry.functions.push_back("Ordinal#" + std::to_string(ord));
            }
            else
            {
                // Import by name - read hint/name
                uint64_t hintNameAddr = baseAddress + (uint32_t)(thunkValue & 0x7FFFFFFF);
                char funcName[256];
                // Skip 2-byte hint
                if (ReadProcessMemory(processHandle, (LPCVOID)(hintNameAddr + 2),
                                       funcName, sizeof(funcName), &bytesRead))
                {
                    funcName[255] = 0;
                    entry.functions.push_back(funcName);
                }
            }
        }

        info.imports.push_back(entry);
    }
}

void PEParser::ParseExports(HANDLE processHandle, uint64_t baseAddress,
                             uint32_t exportDirRVA, bool is64bit, PEInfo& info)
{
    (void)is64bit;
    uint64_t exportAddr = baseAddress + exportDirRVA;
    SIZE_T bytesRead;

    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadProcessMemory(processHandle, (LPCVOID)exportAddr, &exportDir, sizeof(exportDir), &bytesRead))
        return;

    uint32_t numFuncs = exportDir.NumberOfFunctions;
    uint32_t numNames = exportDir.NumberOfNames;
    if (numFuncs == 0 || numFuncs > 10000)
        return;

    std::vector<uint32_t> funcRVAs(numFuncs);
    if (!ReadProcessMemory(processHandle, (LPCVOID)(baseAddress + exportDir.AddressOfFunctions),
                           funcRVAs.data(), numFuncs * sizeof(uint32_t), &bytesRead))
        return;

    std::vector<uint32_t> nameRVAs(numNames);
    std::vector<uint16_t> ordinals(numNames);
    if (numNames > 0)
    {
        ReadProcessMemory(processHandle, (LPCVOID)(baseAddress + exportDir.AddressOfNames),
                           nameRVAs.data(), numNames * sizeof(uint32_t), &bytesRead);
        ReadProcessMemory(processHandle, (LPCVOID)(baseAddress + exportDir.AddressOfNameOrdinals),
                           ordinals.data(), numNames * sizeof(uint16_t), &bytesRead);
    }

    for (uint32_t i = 0; i < numFuncs && i < 2000; ++i)
    {
        if (funcRVAs[i] == 0) continue;

        PEInfo::PEExportEntry ee;
        ee.rva = funcRVAs[i];
        ee.ordinal = (uint16_t)(exportDir.Base + i);
        ee.name = "Ordinal#" + std::to_string(ee.ordinal);

        for (uint32_t j = 0; j < numNames; ++j)
        {
            if (ordinals[j] == i)
            {
                char nameBuf[256];
                if (ReadProcessMemory(processHandle, (LPCVOID)(baseAddress + nameRVAs[j]),
                                       nameBuf, sizeof(nameBuf) - 1, &bytesRead))
                {
                    nameBuf[255] = 0;
                    ee.name = nameBuf;
                }
                break;
            }
        }
        info.exports.push_back(ee);
    }
}

} // namespace kyv
