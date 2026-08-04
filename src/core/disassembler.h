#pragma once
// ============================================================================
// OpenReverse - Core: Disassembler
// x86/x64 disassembly using Capstone engine
// ============================================================================

#include <capstone/capstone.h>
#include <vector>
#include <string>
#include <cstdint>

namespace openreverse {

struct Instruction {
    uint64_t    address;
    uint8_t     bytes[16];
    uint8_t     size;
    std::string mnemonic;
    std::string operands;
    bool        isJump;
    bool        isCall;
    bool        isRet;
    uint64_t    targetAddress; // for jumps/calls
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    // Initialize for architecture (true = x64, false = x86)
    bool Init(bool is64bit);

    // Disassemble raw bytes
    std::vector<Instruction> Disassemble(const uint8_t* code, size_t codeSize,
                                          uint64_t baseAddress, size_t maxInstructions = 100);

    // Get/set syntax
    void SetIntelSyntax(bool intel);
    bool IsInitialized() const { return initialized_; }

private:
    csh         handle_ = 0;
    bool        initialized_ = false;
    bool        is64bit_ = false;

    bool IsJumpMnemonic(const char* mnemonic);
    bool IsCallMnemonic(const char* mnemonic);
    bool IsRetMnemonic(const char* mnemonic);
    uint64_t ExtractTarget(cs_insn* insn);
};

} // namespace openreverse
