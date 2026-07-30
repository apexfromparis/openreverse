#pragma once
// ============================================================================
// KYV - Core: PE Parser
// Parse PE headers from process memory (DOS, NT, sections, imports, exports)
// ============================================================================

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

namespace kyv {

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
};

class PEParser {
public:
    // Parse PE headers from process memory at given base address
    PEInfo Parse(HANDLE processHandle, uint64_t baseAddress);

private:
    void ParseSections(HANDLE processHandle, uint64_t ntHeaderAddr,
                        uint16_t numSections, bool is64bit, PEInfo& info);
    void ParseImports(HANDLE processHandle, uint64_t baseAddress,
                       uint32_t importDirRVA, bool is64bit, PEInfo& info);
};

} // namespace kyv
