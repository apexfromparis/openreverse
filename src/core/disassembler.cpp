#include "disassembler.h"
#include <cstring>
#include <utility>

namespace openreverse {

Disassembler::Disassembler()
{
}

Disassembler::~Disassembler()
{
    if (initialized_)
        cs_close(&handle_);
}

bool Disassembler::Init(bool is64bit)
{
    if (initialized_)
        cs_close(&handle_);

    cs_mode mode = is64bit ? CS_MODE_64 : CS_MODE_32;

    cs_err err = cs_open(CS_ARCH_X86, mode, &handle_);
    if (err != CS_ERR_OK)
    {
        initialized_ = false;
        return false;
    }

    cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    initialized_ = true;
    return true;
}

void Disassembler::SetIntelSyntax(bool intel)
{
    if (initialized_)
        cs_option(handle_, CS_OPT_SYNTAX, intel ? CS_OPT_SYNTAX_INTEL : CS_OPT_SYNTAX_ATT);
}

std::vector<Instruction> Disassembler::Disassemble(const uint8_t* code, size_t codeSize,
                                                     uint64_t baseAddress, size_t maxInstructions)
{
    std::vector<Instruction> result;
    if (!initialized_ || !code || codeSize == 0)
        return result;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle_, code, codeSize, baseAddress, maxInstructions, &insn);

    if (count > 0)
    {
        result.reserve(count);
        for (size_t i = 0; i < count; ++i)
        {
            Instruction inst{};
            PopulateInstruction(&insn[i], inst);
            result.push_back(inst);
        }
        cs_free(insn, count);
    }

    return result;
}

bool Disassembler::DecodeInstruction(const uint8_t* code, size_t codeSize,
                                     uint64_t address, Instruction& instruction)
{
    instruction = Instruction{};
    if (!initialized_ || !code || codeSize == 0)
        return false;

    cs_insn* decoded = nullptr;
    const size_t count = cs_disasm(handle_, code, codeSize, address, 1, &decoded);
    if (count != 1 || !decoded)
        return false;

    PopulateInstruction(decoded, instruction);
    cs_free(decoded, count);
    return instruction.size != 0;
}

void Disassembler::PopulateInstruction(cs_insn* source, Instruction& instruction)
{
    if (!source)
        return;
    instruction.address = source->address;
    instruction.size = static_cast<uint8_t>(source->size);
    memcpy(instruction.bytes, source->bytes, source->size);
    instruction.mnemonic = source->mnemonic;
    instruction.operands = source->op_str;
    instruction.isJump = IsJumpMnemonic(source->mnemonic);
    instruction.isCall = IsCallMnemonic(source->mnemonic);
    instruction.isRet = IsRetMnemonic(source->mnemonic);
    ExtractTarget(source, instruction);
}

bool Disassembler::IsJumpMnemonic(const char* mnemonic)
{
    if (!mnemonic) return false;
    return mnemonic[0] == 'j' || strcmp(mnemonic, "loop") == 0 ||
        strcmp(mnemonic, "loope") == 0 || strcmp(mnemonic, "loopne") == 0;
}

bool Disassembler::IsCallMnemonic(const char* mnemonic)
{
    if (!mnemonic) return false;
    return strcmp(mnemonic, "call") == 0 || strcmp(mnemonic, "lcall") == 0;
}

bool Disassembler::IsRetMnemonic(const char* mnemonic)
{
    if (!mnemonic) return false;
    return strcmp(mnemonic, "ret") == 0 || strcmp(mnemonic, "retn") == 0 ||
        strcmp(mnemonic, "retf") == 0 || strcmp(mnemonic, "retfq") == 0 ||
        strcmp(mnemonic, "iret") == 0 || strcmp(mnemonic, "iretd") == 0 ||
        strcmp(mnemonic, "iretq") == 0;
}

void Disassembler::ExtractTarget(cs_insn* insn, Instruction& instruction)
{
    if (!insn || !insn->detail)
        return;

    cs_x86* x86 = &insn->detail->x86;
    for (int i = 0; i < x86->op_count; ++i)
    {
        const cs_x86_op& operand = x86->operands[i];
        if ((instruction.isCall || instruction.isJump) && operand.type == X86_OP_IMM &&
            instruction.targetKind == InstructionTargetKind::None)
        {
            instruction.targetAddress = static_cast<uint64_t>(operand.imm);
            instruction.targetKind = InstructionTargetKind::Immediate;
        }
        if (operand.type == X86_OP_MEM)
        {
            MemoryOperand memory;
            if (operand.mem.base != X86_REG_INVALID)
                memory.baseRegister = cs_reg_name(handle_, operand.mem.base);
            if (operand.mem.index != X86_REG_INVALID)
                memory.indexRegister = cs_reg_name(handle_, operand.mem.index);
            memory.displacement = operand.mem.disp;
            memory.scale = static_cast<uint32_t>(operand.mem.scale);
            memory.size = operand.size;
            memory.read = (operand.access & CS_AC_READ) != 0;
            memory.write = (operand.access & CS_AC_WRITE) != 0;
            memory.ripRelative = operand.mem.base == X86_REG_RIP || operand.mem.base == X86_REG_EIP;
            instruction.memoryOperands.push_back(std::move(memory));

            uint64_t target = 0;
            // In x64 RIP-relative addressing: [rip + disp]
            if (operand.mem.base == X86_REG_RIP)
            {
                target = static_cast<uint64_t>(insn->address + insn->size + operand.mem.disp);
            }
            // Absolute memory address without base/index register
            else if (operand.mem.base == X86_REG_INVALID &&
                     operand.mem.index == X86_REG_INVALID && operand.mem.disp != 0)
            {
                target = static_cast<uint64_t>(operand.mem.disp);
            }

            if (target == 0 || instruction.targetKind != InstructionTargetKind::None)
                continue;

            instruction.targetAddress = target;
            instruction.targetKind = InstructionTargetKind::Memory;
            instruction.memoryRead = (operand.access & CS_AC_READ) != 0;
            instruction.memoryWrite = (operand.access & CS_AC_WRITE) != 0;
        }
    }
}

} // namespace openreverse
