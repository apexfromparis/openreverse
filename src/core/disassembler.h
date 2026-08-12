#pragma once

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
    uint8_t operandIndex = 0;
    std::string baseRegister;
    std::string indexRegister;
    int64_t displacement = 0;
    uint32_t scale = 1;
    uint8_t size = 0;
    bool read = false;
    bool write = false;
    bool ripRelative = false;
    bool resolved = false;
    uint64_t resolvedAddress = 0;
};

enum class OperandType {
    Register,
    Immediate,
    Memory,
    Invalid
};

struct DecodedOperand {
    OperandType type = OperandType::Invalid;
    uint8_t index = 0;
    uint8_t size = 0;
    bool read = false;
    bool write = false;
    std::string registerName;
    int64_t immediate = 0;
    MemoryOperand memory;
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
    std::vector<DecodedOperand> decodedOperands;
    std::vector<std::string> registersRead;
    std::vector<std::string> registersWritten;
    std::vector<uint8_t> groups;
    unsigned int instructionId = 0;
    uint8_t displacementOffset = 0;
    uint8_t displacementSize = 0;
    uint8_t immediateOffset = 0;
    uint8_t immediateSize = 0;
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    bool Init(bool is64bit);

    std::vector<Instruction> Disassemble(const uint8_t* code, size_t codeSize,
                                          uint64_t baseAddress, size_t maxInstructions = 100);

    // Decode exactly one instruction without scanning bytes beyond it.
    bool DecodeInstruction(const uint8_t* code, size_t codeSize,
                           uint64_t address, Instruction& instruction);

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
