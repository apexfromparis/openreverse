#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "analysis/disassembler.h"
#include "analysis/pe_parser.h"
#include "analysis/symbol_provider.h"

namespace openreverse {

enum class CFGEdgeType {
    Fallthrough,
    ConditionalTrue,
    ConditionalFalse,
    Unconditional,
    Return
};

enum class FunctionSource {
    RuntimeFunction,
    Symbol,
    Export,
    EntryPoint,
    DirectCall,
    RecursiveTraversal,
    Heuristic,
    UserDefined,
    Unknown
};

struct CFGEdge {
    uint64_t source = 0;
    uint64_t target = 0;
    CFGEdgeType type = CFGEdgeType::Fallthrough;
};

struct BasicBlock {
    uint64_t                 startAddress = 0;
    uint64_t                 endAddress = 0;
    std::vector<Instruction> instructions;
    uint64_t                 fallthroughAddr = 0;
    uint64_t                 branchAddr = 0;
    std::vector<uint64_t>    successors;
    std::vector<uint64_t>    predecessors;
    bool                     isTarget = false;
    bool                     isTerminal = false;
};

struct ControlFlowGraph {
    uint64_t                 entryAddress = 0;
    std::vector<BasicBlock>  basicBlocks;
    std::vector<CFGEdge>     edges;
    size_t                   decodedInstructionCount = 0;
    bool                     complete = true;
    bool                     instructionBudgetReached = false;

    const BasicBlock* FindBlock(uint64_t startAddress) const;
    const BasicBlock* FindContainingBlock(uint64_t address) const;
};

struct FunctionInfo {
    uint64_t                 startAddress = 0;
    uint64_t                 endAddress = 0;
    uint64_t                 analysisLimit = 0;
    uint64_t                 analyzedEndAddress = 0;
    std::string              name;
    size_t                   size = 0;
    size_t                   analyzedSize = 0;
    int                      cyclomaticComplexity = 0;
    FunctionSource           source = FunctionSource::Unknown;
    std::vector<FunctionSource> provenance;
    bool                     boundaryKnown = false;
    ControlFlowGraph         cfg;
    std::vector<uint64_t>    callTargets;
    bool                     isExported = false;
    int                      xrefCount = 0;
};

namespace functions {

std::vector<FunctionInfo> DiscoverFunctions(const uint8_t* data, size_t dataSize,
                                            uint64_t baseAddress, bool is64Bit,
                                            size_t maxFunctions = 10000,
                                            size_t maxDiscoveryInstructions = 250000);

std::vector<FunctionInfo> DiscoverFunctionsFromXRefs(const std::vector<FunctionInfo>& existing,
                                                     const std::vector<uint64_t>& callTargets,
                                                     uint64_t codeStart, uint64_t codeEnd, bool is64Bit,
                                                     size_t maxFunctions = 10000);

std::vector<FunctionInfo> DiscoverFunctionsFromPE(const std::vector<FunctionInfo>& existing,
                                                  uint64_t entryPoint,
                                                  const std::vector<uint64_t>& exportAddresses,
                                                  bool is64Bit);

std::vector<FunctionInfo> DiscoverFunctionsFromRuntimeFunctions(
    const std::vector<FunctionInfo>& existing, uint64_t imageBase,
    const std::vector<PERuntimeFunction>& runtimeFunctions, bool is64Bit);

std::vector<FunctionInfo> DiscoverFunctionsFromSymbols(
    const std::vector<FunctionInfo>& existing, uint64_t imageBase, uint64_t imageSize,
    const std::vector<SymbolRecord>& symbols, bool is64Bit,
    size_t maxFunctions = 200000);

FunctionInfo AnalyzeFunction(const uint8_t* data, size_t dataSize,
                             uint64_t functionAddress, uint64_t bufferBase,
                             Disassembler& disasm, bool is64Bit,
                             size_t maxBytes = 4096,
                             size_t maxInstructions = 4096);

// Render only decoded instructions and CFG facts; it does not infer source semantics.
std::string GenerateAssemblySummary(const FunctionInfo& function, bool is64Bit);

} // namespace functions

} // namespace openreverse
