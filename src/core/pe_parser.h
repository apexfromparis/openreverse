#pragma once
// ============================================================================
// OpenReverse - Core: PE Parser
// Parse PE headers from process memory (DOS, NT, sections, imports, exports)
// ============================================================================

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

struct PEInfo {
    bool        valid = false;
    bool        is64bit = false;

    // DOS Header
    uint16_t    dosMagic;
    uint32_t    peOffset;

    // NT Headers
    uint16_t    machine;
    uint16_t    numberOfSections;
    uint32_t    timestamp;
    uint32_t    sizeOfImage;
    uint64_t    entryPoint;
    uint64_t    imageBase;

    // Sections
    std::vector<PESectionInfo> sections;

    // Imports
    std::vector<PEImportEntry> imports;

    // Exports
    struct PEExportEntry {
        std::string name;
        uint32_t    rva;
        uint16_t    ordinal;
    };
    std::vector<PEExportEntry> exports;
};

class PEParser {
public:
    // Parse PE headers from process memory at given base address
    PEInfo Parse(HANDLE processHandle, uint64_t baseAddress);

    // Parse PE headers directly from an offline disk file (.sys, .exe, .dll)
    PEInfo ParseFile(const std::string& filePath, std::vector<uint8_t>& rawBufferOut);

private:
    void ParseSections(HANDLE processHandle, uint64_t ntHeaderAddr,
                        uint16_t numSections, bool is64bit, PEInfo& info);
    void ParseImports(HANDLE processHandle, uint64_t baseAddress,
                       uint32_t importDirRVA, bool is64bit, PEInfo& info);
    void ParseExports(HANDLE processHandle, uint64_t baseAddress,
                       uint32_t exportDirRVA, bool is64bit, PEInfo& info);
    void ParseImportsOffline(const uint8_t* data, size_t fileSize,
                              uint32_t importDirRVA, bool is64bit, PEInfo& info);
    void ParseExportsOffline(const uint8_t* data, size_t fileSize,
                              uint32_t exportDirRVA, bool is64bit, PEInfo& info);
    static uint32_t RvaToOffset(uint32_t rva, const std::vector<PESectionInfo>& sections, size_t fileSize);
};

} // namespace openreverse
