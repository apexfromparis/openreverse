#pragma once

#include "core/disassembler.h"

namespace openreverse {

enum class ControlFlowSemantic {
    Linear,
    Call,
    ConditionalBranch,
    UnconditionalBranch,
    Return,
    Interrupt
};

bool HasInstructionGroup(const Instruction& instruction, uint8_t group);
ControlFlowSemantic ClassifyControlFlow(const Instruction& instruction);
bool IsMovePropagationInstruction(const Instruction& instruction);
bool IsAddressCalculationInstruction(const Instruction& instruction);

} // namespace openreverse
