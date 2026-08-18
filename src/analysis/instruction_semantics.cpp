#include "analysis/instruction_semantics.h"

#include <algorithm>
#include <capstone/x86.h>

namespace openreverse {

namespace {

bool IsConditionalBranchId(unsigned int id)
{
    switch (id)
    {
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JCXZ:
    case X86_INS_JE:
    case X86_INS_JECXZ:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JRCXZ:
    case X86_INS_JS:
    case X86_INS_LOOP:
    case X86_INS_LOOPE:
    case X86_INS_LOOPNE:
        return true;
    default:
        return false;
    }
}

} // namespace

bool HasInstructionGroup(const Instruction& instruction, uint8_t group)
{
    return std::find(instruction.groups.begin(), instruction.groups.end(), group) !=
           instruction.groups.end();
}

ControlFlowSemantic ClassifyControlFlow(const Instruction& instruction)
{
    if (HasInstructionGroup(instruction, CS_GRP_RET) ||
        HasInstructionGroup(instruction, CS_GRP_IRET))
        return ControlFlowSemantic::Return;
    if (HasInstructionGroup(instruction, CS_GRP_CALL))
        return ControlFlowSemantic::Call;
    if (instruction.instructionId == X86_INS_JMP ||
        instruction.instructionId == X86_INS_LJMP)
        return ControlFlowSemantic::UnconditionalBranch;
    if (HasInstructionGroup(instruction, CS_GRP_JUMP) ||
        IsConditionalBranchId(instruction.instructionId))
    {
        return ControlFlowSemantic::ConditionalBranch;
    }
    if (HasInstructionGroup(instruction, CS_GRP_INT))
        return ControlFlowSemantic::Interrupt;
    return ControlFlowSemantic::Linear;
}

bool IsMovePropagationInstruction(const Instruction& instruction)
{
    switch (instruction.instructionId)
    {
    case X86_INS_MOV:
    case X86_INS_MOVABS:
    case X86_INS_MOVSX:
    case X86_INS_MOVSXD:
    case X86_INS_MOVZX:
        return true;
    default:
        return false;
    }
}

bool IsAddressCalculationInstruction(const Instruction& instruction)
{
    return instruction.instructionId == X86_INS_LEA;
}

} // namespace openreverse
