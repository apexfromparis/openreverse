#include "disassembler.h"
#include "analysis/instruction_semantics.h"
#include <cstring>
#include <limits>
#include <utility>

namespace openreverse {

namespace {

bool AddDisplacement(uint64_t base, int64_t displacement, uint64_t& target)
{
    if (displacement >= 0)
    {
        const uint64_t value = static_cast<uint64_t>(displacement);
        if (value > (std::numeric_limits<uint64_t>::max)() - base)
            return false;
        target = base + value;
        return true;
    }
    const uint64_t magnitude = static_cast<uint64_t>(-(displacement + 1)) + 1;
    if (magnitude > base)
        return false;
    target = base - magnitude;
    return true;
}

} // namespace

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
    instruction.instructionId = source->id;
    instruction.size = static_cast<uint8_t>(source->size);
    memcpy(instruction.bytes, source->bytes, source->size);
    instruction.mnemonic = source->mnemonic;
    instruction.operands = source->op_str;
    if (source->detail)
    {
        instruction.displacementOffset = source->detail->x86.encoding.disp_offset;
        instruction.displacementSize = source->detail->x86.encoding.disp_size;
        instruction.immediateOffset = source->detail->x86.encoding.imm_offset;
        instruction.immediateSize = source->detail->x86.encoding.imm_size;
        for (uint8_t index = 0; index < source->detail->groups_count; ++index)
            instruction.groups.push_back(source->detail->groups[index]);

        cs_regs readRegisters{};
        cs_regs writtenRegisters{};
        uint8_t readCount = 0;
        uint8_t writtenCount = 0;
        if (cs_regs_access(handle_, source, readRegisters, &readCount,
                           writtenRegisters, &writtenCount) == CS_ERR_OK)
        {
            for (uint8_t index = 0; index < readCount; ++index)
                instruction.registersRead.emplace_back(cs_reg_name(handle_, readRegisters[index]));
            for (uint8_t index = 0; index < writtenCount; ++index)
                instruction.registersWritten.emplace_back(cs_reg_name(handle_, writtenRegisters[index]));
        }
    }
    const ControlFlowSemantic semantic = ClassifyControlFlow(instruction);
    instruction.isCall = semantic == ControlFlowSemantic::Call;
    instruction.isConditionalBranch = semantic == ControlFlowSemantic::ConditionalBranch;
    instruction.isUnconditionalBranch = semantic == ControlFlowSemantic::UnconditionalBranch;
    instruction.isJump = instruction.isConditionalBranch || instruction.isUnconditionalBranch;
    instruction.isRet = semantic == ControlFlowSemantic::Return;
    instruction.isInterrupt = semantic == ControlFlowSemantic::Interrupt;
    ExtractTarget(source, instruction);
}

void Disassembler::ExtractTarget(cs_insn* insn, Instruction& instruction)
{
    if (!insn || !insn->detail)
        return;

    cs_x86* x86 = &insn->detail->x86;
    for (int i = 0; i < x86->op_count; ++i)
    {
        const cs_x86_op& operand = x86->operands[i];
        DecodedOperand decoded;
        decoded.index = static_cast<uint8_t>(i);
        decoded.size = operand.size;
        decoded.read = (operand.access & CS_AC_READ) != 0;
        decoded.write = (operand.access & CS_AC_WRITE) != 0;
        if ((instruction.isCall || instruction.isJump) && operand.type == X86_OP_IMM &&
            instruction.targetKind == InstructionTargetKind::None)
        {
            instruction.targetAddress = static_cast<uint64_t>(operand.imm);
            instruction.targetKind = InstructionTargetKind::Immediate;
        }
        if (operand.type == X86_OP_REG)
        {
            decoded.type = OperandType::Register;
            decoded.registerName = cs_reg_name(handle_, operand.reg);
        }
        else if (operand.type == X86_OP_IMM)
        {
            decoded.type = OperandType::Immediate;
            decoded.immediate = operand.imm;
        }
        if (operand.type == X86_OP_MEM)
        {
            decoded.type = OperandType::Memory;
            MemoryOperand memory;
            memory.operandIndex = static_cast<uint8_t>(i);
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
            uint64_t target = 0;
            if (operand.mem.base == X86_REG_RIP)
            {
                AddDisplacement(insn->address + insn->size, operand.mem.disp, target);
            }
            else if (operand.mem.base == X86_REG_INVALID &&
                     operand.mem.index == X86_REG_INVALID && operand.mem.disp != 0)
            {
                target = static_cast<uint64_t>(operand.mem.disp);
            }

            memory.resolved = target != 0;
            memory.resolvedAddress = target;
            decoded.memory = memory;
            instruction.memoryOperands.push_back(std::move(memory));

            if (target != 0 && instruction.targetKind == InstructionTargetKind::None)
            {
                instruction.targetAddress = target;
                instruction.targetKind = InstructionTargetKind::Memory;
                instruction.memoryRead = decoded.read;
                instruction.memoryWrite = decoded.write;
            }
        }
        instruction.decodedOperands.push_back(std::move(decoded));
    }
}

} // namespace openreverse
