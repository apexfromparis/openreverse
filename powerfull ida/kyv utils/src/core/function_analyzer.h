#pragma once
// ============================================================================
// KYV - Core: Function Analyzer & CFG / Decompiler Engine
// Advanced IDA Pro style function discovery, basic blocks, and pseudocode
// ============================================================================

#include <string>
#include <vector>
#include <cstdint>
#include <map>
#include <set>
#include <windows.h>
#include "core/disassembler.h"

namespace kyv {

struct BasicBlock {
    uint64_t                 startAddress = 0;
    uint64_t                 endAddress = 0;
    std::vector<Instruction> instructions;
    uint64_t                 fallthroughAddr = 0;
    uint64_t                 branchAddr = 0;
    bool                     isTarget = false;
    bool                     isTerminal = false;
};

struct FunctionInfo {
    uint64_t                 startAddress = 0;
    uint64_t                 endAddress = 0;
    std::string              name;
    size_t                   size = 0;
    int                      cyclomaticComplexity = 1;
    std::string              callingConvention = "fastcall";
    std::vector<BasicBlock>  basicBlocks;
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
                                                size_t maxFunctions = 500);

    // Build full CFG & basic blocks for a single function
    FunctionInfo AnalyzeFunction(const uint8_t* data, size_t dataSize,
                                 uint64_t funcAddress, uint64_t bufferBase,
                                 Disassembler& disasm, bool is64Bit,
                                 size_t maxBytes = 4096);

    // Generate C-like Pseudocode (Hex-Rays equivalent) from a FunctionInfo
    std::string GeneratePseudocode(const FunctionInfo& func, bool is64Bit) const;

    // Utility: check if instruction mnemonic is a conditional branch
    static bool IsConditionalJump(const std::string& mnemonic);
    static bool IsUnconditionalJump(const std::string& mnemonic);
    static bool IsReturn(const std::string& mnemonic);
    static bool IsCall(const std::string& mnemonic);
};

} // namespace kyv
