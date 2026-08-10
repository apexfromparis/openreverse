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

struct GlobalCandidate {
    uint64_t address = 0;
    uint64_t moduleOffset = 0;
    std::string name;
    std::string sectionName;
    size_t readCount = 0;
    size_t writeCount = 0;
    size_t addressCount = 0;
    float confidence = 0.0f;
    std::vector<uint64_t> accessSites;
};

struct FieldAccessCandidate {
    uint64_t instructionAddress = 0;
    uint64_t functionAddress = 0;
    uint64_t offset = 0;
    uint8_t operandSize = 0;
    DataAccessType access = DataAccessType::Read;
    std::string baseRegister;
    std::string instructionText;
};

struct StructureFieldCandidate {
    uint64_t offset = 0;
    uint8_t size = 0;
    size_t readCount = 0;
    size_t writeCount = 0;
    size_t addressCount = 0;
    std::vector<uint64_t> accessSites;
};

struct StructureCandidate {
    std::string name;
    uint64_t functionAddress = 0;
    std::string baseRegister;
    uint64_t estimatedSize = 0;
    float confidence = 0.0f;
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
