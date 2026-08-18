#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

namespace openreverse {

struct PESectionInfo {
    char        name[9];
    uint32_t    virtualAddress;
    uint32_t    virtualSize;
    uint32_t    rawDataOffset;
    uint32_t    rawDataSize;
    uint32_t    characteristics;
};

struct PEImportEntry {
    std::string dllName;
    std::vector<std::string> functions;
};

struct PERuntimeFunction {
    uint32_t beginRva = 0;
    uint32_t endRva = 0;
    uint32_t unwindInfoRva = 0;
};

struct PEInfo {
    bool        valid = false;
    bool        is64bit = false;

    uint16_t    dosMagic = 0;
    uint32_t    peOffset = 0;

    uint16_t    machine = 0;
    uint16_t    numberOfSections = 0;
    uint32_t    timestamp = 0;
    uint32_t    sizeOfImage = 0;
    uint32_t    sizeOfHeaders = 0;
    uint64_t    entryPoint = 0;
    uint64_t    imageBase = 0;

    uint32_t    exceptionDirectoryRva = 0;
    uint32_t    exceptionDirectorySize = 0;
    uint32_t    importDirectoryRva = 0;
    uint32_t    exportDirectoryRva = 0;
    uint32_t    exportDirectorySize = 0;
    uint32_t    debugDirectoryRva = 0;
    uint32_t    debugDirectorySize = 0;
    std::string pdbGuid;
    uint32_t    pdbAge = 0;
    std::string pdbPath;
    bool        runtimeFunctionDirectoryComplete = true;
    size_t      rejectedRuntimeFunctionCount = 0;

    std::vector<PESectionInfo> sections;

    std::vector<PEImportEntry> imports;
    std::vector<PERuntimeFunction> runtimeFunctions;

    struct PEExportEntry {
        std::string name;
        uint32_t    rva = 0;
        uint32_t    ordinal = 0;
        bool        isForwarder = false;
        std::string forwarder;
    };
    std::vector<PEExportEntry> exports;
};

class PEParser {
public:
    PEInfo Parse(HANDLE processHandle, uint64_t baseAddress, uint64_t mappedImageSize);

    PEInfo ParseFile(const std::string& filePath, std::vector<uint8_t>& rawBufferOut);

    PEInfo ParseBuffer(const uint8_t* data, size_t fileSize);

    // Parse PE metadata from an RVA-mapped image supplied by the user.
    PEInfo ParseMappedImage(const uint8_t* data, size_t mappedImageSize,
                            uint64_t imageBaseOverride = 0);

    // Resolve a disk-backed RVA. Virtual zero-fill has no raw file offset.
    static bool RvaToFileOffset(uint32_t rva, size_t requiredSize, const PEInfo& info,
                                size_t fileSize, size_t& offsetOut);

    static bool BuildMappedImage(const std::vector<uint8_t>& rawBuffer, const PEInfo& info,
                                 std::vector<uint8_t>& mappedImageOut);

private:
    bool ParseSections(HANDLE processHandle, uint64_t baseAddress, uint64_t mappedImageSize,
                       uint64_t sectionTableRVA, uint16_t numSections, PEInfo& info);
    void ParseImports(HANDLE processHandle, uint64_t baseAddress, uint64_t mappedImageSize,
                      uint32_t importDirRVA, bool is64bit, PEInfo& info);
    void ParseExports(HANDLE processHandle, uint64_t baseAddress, uint64_t mappedImageSize,
                      uint32_t exportDirRVA, uint32_t exportDirSize, bool is64bit, PEInfo& info);
    void ParseImportsOffline(const uint8_t* data, size_t fileSize,
                              uint32_t importDirRVA, bool is64bit, PEInfo& info);
    void ParseExportsOffline(const uint8_t* data, size_t fileSize,
                               uint32_t exportDirRVA, uint32_t exportDirSize, bool is64bit, PEInfo& info);
    void ParseRuntimeFunctionsRaw(const uint8_t* data, size_t fileSize, PEInfo& info);
    void ParseRuntimeFunctionsMapped(const uint8_t* data, size_t mappedImageSize, PEInfo& info);
    void ParseImportsMapped(const uint8_t* data, size_t mappedImageSize, PEInfo& info);
    void ParseExportsMapped(const uint8_t* data, size_t mappedImageSize, PEInfo& info);
    void ParseCodeViewRaw(const uint8_t* data, size_t fileSize, PEInfo& info);
    void ParseCodeViewMapped(const uint8_t* data, size_t mappedImageSize, PEInfo& info);
    void ParseCodeViewLive(HANDLE processHandle, uint64_t baseAddress,
                           uint64_t mappedImageSize, PEInfo& info);
};

} // namespace openreverse
