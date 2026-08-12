#pragma once
// OpenReverse - Core: Function Analyzer, CFG, and Experimental Pseudocode

#include <string>
#include <vector>
#include <cstdint>
#include <map>
#include <set>
#include <windows.h>
#include "core/disassembler.h"

namespace openreverse {

enum class CFGEdgeType {
    Fallthrough,
    ConditionalTrue,
    ConditionalFalse,
    Unconditional,
    Return
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
    std::string              name;
    size_t                   size = 0;
    int                      cyclomaticComplexity = 1;
    std::string              callingConvention = "fastcall";
    ControlFlowGraph         cfg;
    std::vector<uint64_t>    callTargets;
    bool                     isExported = false;
    int                      xrefCount = 0;
};

class FunctionAnalyzer {
public:
    FunctionAnalyzer() = default;
    ~FunctionAnalyzer() = default;

    // Discover functions inside a memory buffer (.text section)
    std::vector<FunctionInfo> DiscoverFunctions(const uint8_t* data, size_t dataSize,
                                                uint64_t baseAddress, bool is64Bit,
                                                size_t maxFunctions = 10000,
                                                size_t maxDiscoveryInstructions = 250000);

    // Discover additional functions by analyzing CALL targets from XREFs and CFG branches
    std::vector<FunctionInfo> DiscoverFunctionsFromXRefs(const std::vector<FunctionInfo>& existing,
                                                         const std::vector<uint64_t>& callTargets,
                                                         uint64_t codeStart, uint64_t codeEnd, bool is64Bit,
                                                         size_t maxFunctions = 10000);

    // Discover exported and entry point functions from PE headers
    std::vector<FunctionInfo> DiscoverFunctionsFromPE(const std::vector<FunctionInfo>& existing,
                                                      uint64_t entryPoint,
                                                      const std::vector<uint64_t>& exportAddresses,
                                                      bool is64Bit);

    // Build full CFG & basic blocks for a single function
    FunctionInfo AnalyzeFunction(const uint8_t* data, size_t dataSize,
                                 uint64_t funcAddress, uint64_t bufferBase,
                                 Disassembler& disasm, bool is64Bit,
                                 size_t maxBytes = 4096,
                                 size_t maxInstructions = 4096);

    // Generate an experimental C-like assembly summary from a FunctionInfo.
    std::string GeneratePseudocode(const FunctionInfo& func, bool is64Bit) const;

    // Utility: check if instruction mnemonic is a conditional branch
    static bool IsConditionalJump(const std::string& mnemonic);
    static bool IsUnconditionalJump(const std::string& mnemonic);
    static bool IsReturn(const std::string& mnemonic);
    static bool IsCall(const std::string& mnemonic);
};

} // namespace openreverse
