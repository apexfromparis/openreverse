#pragma once

#include "core/disassembler.h"
#include "core/function_analyzer.h"
#include "core/module_manager.h"
#include "core/pe_parser.h"
#include "core/xref_scanner.h"

#include <cstdint>
#include <string>
#include <vector>

namespace openreverse {

enum class DataAccessType {
    Read,
    Write,
    ReadWrite,
    Address
};

enum class EvidenceLevel {
    Known,
    Inferred,
    Heuristic,
    Partial,
    Unknown
};

enum class GlobalKind {
    GlobalCandidate,
    ImportThunk,
    StringReference,
    ReadonlyData,
    WritableData,
    UnknownData
};

enum class RegisterOriginKind {
    Unknown,
    Argument,
    RegisterCopy,
    StackLocal
};

struct GlobalCandidate {
    uint64_t address = 0;
    uint64_t moduleOffset = 0;
    uint64_t rva = 0;
    std::string name;
    std::string sectionName;
    GlobalKind kind = GlobalKind::UnknownData;
    size_t readCount = 0;
    size_t writeCount = 0;
    size_t addressCount = 0;
    uint32_t evidenceScore = 0;
    EvidenceLevel evidence = EvidenceLevel::Inferred;
    std::vector<uint64_t> accessSites;
    std::vector<uint64_t> sourceFunctions;
    std::vector<uint8_t> operandWidths;
    std::vector<XRefEntry> xrefs;
};

struct FieldAccessCandidate {
    uint64_t instructionAddress = 0;
    uint64_t functionAddress = 0;
    int64_t displacement = 0;
    int64_t offset = 0;
    uint8_t operandSize = 0;
    uint8_t operandIndex = 0;
    DataAccessType access = DataAccessType::Read;
    std::string baseRegister;
    std::string indexRegister;
    uint32_t scale = 1;
    RegisterOriginKind originKind = RegisterOriginKind::Unknown;
    std::string originRegister;
    uint8_t argumentIndex = 0;
    int64_t originAdjustment = 0;
    std::string instructionText;
};

struct StructureFieldCandidate {
    int64_t offset = 0;
    uint8_t size = 0;
    size_t readCount = 0;
    size_t writeCount = 0;
    size_t addressCount = 0;
    std::vector<uint64_t> accessSites;
    std::vector<std::string> baseRegisters;
    std::vector<uint64_t> observingFunctions;
};

struct StructureCandidate {
    std::string name;
    uint64_t functionAddress = 0;
    std::string baseRegister;
    uint64_t estimatedSize = 0;
    uint32_t evidenceScore = 0;
    EvidenceLevel evidence = EvidenceLevel::Heuristic;
    RegisterOriginKind originKind = RegisterOriginKind::Unknown;
    uint8_t argumentIndex = 0;
    std::vector<StructureFieldCandidate> fields;
};

std::vector<GlobalCandidate> FindGlobalCandidates(const ModuleInfo& module, const PEInfo& pe,
                                                  const std::vector<XRefEntry>& xrefs);
std::vector<FieldAccessCandidate> FindFieldAccesses(
    const std::vector<Instruction>& instructions, size_t maxCandidates = 100000);
void AssignFieldFunctions(std::vector<FieldAccessCandidate>& fields,
                          const std::vector<FunctionInfo>& functions);
std::vector<StructureCandidate> InferStructures(const std::vector<FieldAccessCandidate>& fields);

} // namespace openreverse
