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

enum class InstructionTargetKind {
    None,
    Immediate,
    Memory
};

struct MemoryOperand {
    std::string baseRegister;
    std::string indexRegister;
    int64_t displacement = 0;
    uint32_t scale = 1;
    uint8_t size = 0;
    bool read = false;
    bool write = false;
    bool ripRelative = false;
};

struct Instruction {
    uint64_t    address = 0;
    uint8_t     bytes[16]{};
    uint8_t     size = 0;
    std::string mnemonic;
    std::string operands;
    bool        isJump = false;
    bool        isCall = false;
    bool        isRet = false;
    uint64_t    targetAddress = 0;
    InstructionTargetKind targetKind = InstructionTargetKind::None;
    bool        memoryRead = false;
    bool        memoryWrite = false;
    std::vector<MemoryOperand> memoryOperands;
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

    // Decode exactly one instruction without scanning bytes beyond it.
    bool DecodeInstruction(const uint8_t* code, size_t codeSize,
                           uint64_t address, Instruction& instruction);

    // Get/set syntax
    void SetIntelSyntax(bool intel);
    bool IsInitialized() const { return initialized_; }

private:
    csh         handle_ = 0;
    bool        initialized_ = false;

    bool IsJumpMnemonic(const char* mnemonic);
    bool IsCallMnemonic(const char* mnemonic);
    bool IsRetMnemonic(const char* mnemonic);
    void PopulateInstruction(cs_insn* source, Instruction& instruction);
    void ExtractTarget(cs_insn* insn, Instruction& instruction);
};

} // namespace openreverse
