#pragma once
// OpenReverse - Core: PE Parser
// Parse PE headers from process memory (DOS, NT, sections, imports, exports)

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
    uint16_t    dosMagic = 0;
    uint32_t    peOffset = 0;

    // NT Headers
    uint16_t    machine = 0;
    uint16_t    numberOfSections = 0;
    uint32_t    timestamp = 0;
    uint32_t    sizeOfImage = 0;
    uint32_t    sizeOfHeaders = 0;
    uint64_t    entryPoint = 0;
    uint64_t    imageBase = 0;

    std::vector<PESectionInfo> sections;

    std::vector<PEImportEntry> imports;

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
    // Parse a loaded PE image within its enumerated module bounds.
    PEInfo Parse(HANDLE processHandle, uint64_t baseAddress, uint64_t mappedImageSize);

    // Parse PE headers directly from an offline disk file (.sys, .exe, .dll)
    PEInfo ParseFile(const std::string& filePath, std::vector<uint8_t>& rawBufferOut);

    // Parse a raw PE file buffer. Exposed for safe fixtures and non-file inputs.
    PEInfo ParseBuffer(const uint8_t* data, size_t fileSize);

    // Resolve a disk-backed RVA. Virtual zero-fill has no raw file offset.
    static bool RvaToFileOffset(uint32_t rva, size_t requiredSize, const PEInfo& info,
                                size_t fileSize, size_t& offsetOut);

    // Map raw headers and sections to their RVAs for VA-based offline analysis.
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
};

} // namespace openreverse
