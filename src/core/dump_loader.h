#pragma once

#include "core/module_manager.h"
#include "core/pe_parser.h"

#include <cstdint>
#include <string>
#include <vector>

namespace openreverse {

enum class DumpRepresentation {
    AutoDetect,
    MappedPEImage,
    RawSnapshot,
    Minidump
};

enum class DumpArchitecture {
    Unknown,
    X86,
    X64
};

struct DumpImportOptions {
    DumpRepresentation representation = DumpRepresentation::AutoDetect;
    DumpArchitecture architecture = DumpArchitecture::Unknown;
    uint64_t imageBase = 0;
    uint64_t moduleSize = 0;
    uint64_t minidumpModuleBase = 0;
};

struct DumpModuleMetadata {
    std::string name;
    uint64_t imageBase = 0;
    uint32_t imageSize = 0;
    uint32_t timestamp = 0;
};

struct DumpLoadResult {
    bool success = false;
    DumpRepresentation representation = DumpRepresentation::AutoDetect;
    DumpArchitecture architecture = DumpArchitecture::Unknown;
    std::string error;
    ModuleInfo module;
    PEInfo pe;
    std::vector<uint8_t> imageBytes;
    std::vector<DumpModuleMetadata> availableModules;
};

class DumpLoader {
public:
    DumpLoadResult Load(const std::string& path,
                        const DumpImportOptions& options = {}) const;
};

} // namespace openreverse
