#pragma once

#include "core/data_analyzer.h"
#include "core/pe_parser.h"
#include "core/signature_engine.h"

#include <cstdint>
#include <string>
#include <vector>

namespace openreverse {

enum class OffsetKind {
    GlobalRva,
    StructureField,
    FunctionRva,
    ImportRva,
    ExportRva,
    PatternMatch,
    UserDefined
};

struct ModuleIdentity {
    std::string name;
    std::string sha256;
    uint32_t peTimestamp = 0;
    uint32_t imageSize = 0;
    uint64_t imageBase = 0;
    std::string fileVersion;
    std::string pdbGuid;
    uint32_t pdbAge = 0;
};

struct OffsetRecord {
    std::string stableId;
    std::string name;
    OffsetKind kind = OffsetKind::UserDefined;
    uint64_t address = 0;
    uint64_t rva = 0;
    int64_t fieldOffset = 0;
    std::string module;
    std::string section;
    uint64_t sourceFunction = 0;
    uint64_t sourceInstruction = 0;
    DataAccessType accessType = DataAccessType::Address;
    uint8_t operandWidth = 0;
    EvidenceLevel evidence = EvidenceLevel::Unknown;
    uint32_t evidenceScore = 0;
    std::vector<std::string> provenance;
};

struct OffsetProject {
    uint32_t schemaVersion = 1;
    ModuleIdentity module;
    std::vector<OffsetRecord> offsets;
    std::vector<SignatureRecord> signatures;
};

bool ComputeModuleIdentity(const std::vector<uint8_t>& bytes, const PEInfo& pe,
                           const std::string& moduleName, ModuleIdentity& identity,
                           std::string& error);
std::string SerializeOffsetProject(const OffsetProject& project);
bool ParseOffsetProject(const std::string& jsonText, OffsetProject& project, std::string& error);
std::string ExportOffsetHeader(const OffsetProject& project);
std::string SanitizeCppIdentifier(const std::string& value);

} // namespace openreverse
