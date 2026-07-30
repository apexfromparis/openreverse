// ============================================================================
// KYV - Core: Disassembler Implementation
// ============================================================================

#include "disassembler.h"
#include <cstring>

namespace kyv {

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

    is64bit_ = is64bit;
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
            Instruction inst;
            inst.address = insn[i].address;
            inst.size = (uint8_t)insn[i].size;
            memcpy(inst.bytes, insn[i].bytes, insn[i].size);
            inst.mnemonic = insn[i].mnemonic;
            inst.operands = insn[i].op_str;
            inst.isJump = IsJumpMnemonic(insn[i].mnemonic);
            inst.isCall = IsCallMnemonic(insn[i].mnemonic);
            inst.isRet  = IsRetMnemonic(insn[i].mnemonic);
            inst.targetAddress = ExtractTarget(&insn[i]);

            result.push_back(inst);
        }
        cs_free(insn, count);
    }

    return result;
}

bool Disassembler::IsJumpMnemonic(const char* mnemonic)
{
    if (!mnemonic) return false;
    return mnemonic[0] == 'j'; // jmp, je, jne, jg, jl, etc.
}

bool Disassembler::IsCallMnemonic(const char* mnemonic)
{
    if (!mnemonic) return false;
    return strcmp(mnemonic, "call") == 0;
}

bool Disassembler::IsRetMnemonic(const char* mnemonic)
{
    if (!mnemonic) return false;
    return strcmp(mnemonic, "ret") == 0 || strcmp(mnemonic, "retn") == 0;
}

uint64_t Disassembler::ExtractTarget(cs_insn* insn)
{
    if (!insn || !insn->detail)
        return 0;

    cs_x86* x86 = &insn->detail->x86;
    for (int i = 0; i < x86->op_count; ++i)
    {
        if (x86->operands[i].type == X86_OP_IMM)
            return (uint64_t)x86->operands[i].imm;
    }
    return 0;
}

} // namespace kyv
