// ============================================================================
// KYV - Core: Function Analyzer & CFG / Decompiler Engine Implementation
// ============================================================================

#include "function_analyzer.h"
#include "utils/helpers.h"
#include "utils/logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>

namespace kyv {

bool FunctionAnalyzer::IsConditionalJump(const std::string& m)
{
    if (m.empty() || m[0] != 'j') return false;
    return m == "je" || m == "jne" || m == "jz" || m == "jnz" ||
           m == "jg" || m == "jge" || m == "jl" || m == "jle" ||
           m == "ja" || m == "jae" || m == "jb" || m == "jbe" ||
           m == "js" || m == "jns" || m == "jo" || m == "jno" ||
           m == "jp" || m == "jnp" || m == "jcxz" || m == "jecxz" || m == "jrcxz";
}

bool FunctionAnalyzer::IsUnconditionalJump(const std::string& m)
{
    return m == "jmp" || m == "ljmp";
}

bool FunctionAnalyzer::IsReturn(const std::string& m)
{
    return m == "ret" || m == "retn" || m == "retf" || m == "iret" || m == "iretd" || m == "iretq";
}

bool FunctionAnalyzer::IsCall(const std::string& m)
{
    return m == "call" || m == "lcall";
}

std::vector<FunctionInfo> FunctionAnalyzer::DiscoverFunctions(const uint8_t* data, size_t dataSize,
                                                            uint64_t baseAddress, bool is64Bit,
                                                            size_t maxFunctions)
{
    std::vector<FunctionInfo> functions;
    if (!data || dataSize < 16) return functions;

    // Scan for standard x64 / x86 prologues
    // 0x48 0x89 0x5c 0x24 (mov [rsp+18h], rbx)
    // 0x48 0x83 0xec (sub rsp, imm)
    // 0x40 0x53 0x48 0x83 0xec (push rbx; sub rsp, imm)
    // 0x55 0x48 0x8b 0xec (push rbp; mov rbp, rsp) - x64
    // 0x55 0x8b 0xec (push ebp; mov ebp, esp) - x86
    for (size_t i = 0; i + 4 < dataSize && functions.size() < maxFunctions; ++i)
    {
        bool isPrologue = false;
        if (is64Bit)
        {
            if (data[i] == 0x48 && data[i + 1] == 0x89 && data[i + 2] == 0x5C && data[i + 3] == 0x24)
                isPrologue = true;
            else if (data[i] == 0x48 && data[i + 1] == 0x83 && data[i + 2] == 0xEC && data[i + 3] >= 0x18)
                isPrologue = true;
            else if (i + 5 < dataSize && data[i] == 0x40 && data[i + 1] == 0x53 && data[i + 2] == 0x48 && data[i + 3] == 0x83 && data[i + 4] == 0xEC)
                isPrologue = true;
            else if (data[i] == 0x55 && data[i + 1] == 0x48 && data[i + 2] == 0x8B && data[i + 3] == 0xEC)
                isPrologue = true;
            else if (data[i] == 0x4C && data[i + 1] == 0x89 && (data[i + 2] == 0x44 || data[i + 2] == 0x4C) && data[i + 3] == 0x24)
                isPrologue = true;
        }
        else
        {
            if (data[i] == 0x55 && data[i + 1] == 0x8B && data[i + 2] == 0xEC)
                isPrologue = true;
            else if (data[i] == 0x83 && data[i + 1] == 0xEC && data[i + 2] >= 0x08)
                isPrologue = true;
        }

        if (isPrologue)
        {
            // Make sure not already inside previous function range
            uint64_t addr = baseAddress + i;
            if (!functions.empty() && addr < functions.back().endAddress)
                continue;

            FunctionInfo fi;
            fi.startAddress = addr;
            // Estimate default end address (will be refined by CFG analysis)
            fi.endAddress = addr + 128;
            fi.size = 128;
            fi.name = "sub_" + helpers::FormatAddress(addr, is64Bit).substr(2);
            fi.callingConvention = is64Bit ? "x64 fastcall (RCX, RDX, R8, R9)" : "x86 stdcall / cdecl";
            functions.push_back(fi);

            i += 16; // Jump ahead to avoid overlapping signatures
        }
    }

    return functions;
}

FunctionInfo FunctionAnalyzer::AnalyzeFunction(const uint8_t* data, size_t dataSize,
                                               uint64_t funcAddress, uint64_t bufferBase,
                                               Disassembler& disasm, bool is64Bit,
                                               size_t maxBytes)
{
    FunctionInfo fi;
    fi.startAddress = funcAddress;
    fi.name = "sub_" + helpers::FormatAddress(funcAddress, is64Bit).substr(2);
    fi.callingConvention = is64Bit ? "x64 fastcall" : "stdcall / cdecl";

    if (!data || funcAddress < bufferBase || (funcAddress - bufferBase) >= dataSize)
        return fi;

    size_t offset = (size_t)(funcAddress - bufferBase);
    size_t remaining = dataSize - offset;
    size_t scanLen = (remaining < maxBytes) ? remaining : maxBytes;

    auto insts = disasm.Disassemble(data + offset, scanLen, funcAddress, 512);
    if (insts.empty()) return fi;

    // First pass: collect jump targets inside this function
    std::set<uint64_t> jumpTargets;
    jumpTargets.insert(funcAddress);

    for (const auto& ins : insts)
    {
        if (ins.isCall && ins.targetAddress != 0)
        {
            fi.callTargets.push_back(ins.targetAddress);
        }
        else if (ins.isJump && ins.targetAddress != 0)
        {
            if (ins.targetAddress >= funcAddress && ins.targetAddress < (funcAddress + scanLen))
                jumpTargets.insert(ins.targetAddress);
        }
        if (IsReturn(ins.mnemonic))
        {
            fi.endAddress = ins.address + ins.size;
        }
    }

    if (fi.endAddress == 0)
        fi.endAddress = insts.back().address + insts.back().size;
    fi.size = (size_t)(fi.endAddress - fi.startAddress);

    // Second pass: build basic blocks
    BasicBlock currentBlock;
    currentBlock.startAddress = insts[0].address;
    currentBlock.isTarget = true;

    int edgeCount = 0;

    for (size_t i = 0; i < insts.size(); ++i)
    {
        const auto& ins = insts[i];
        if (ins.address >= fi.endAddress)
            break;

        // If this address is a jump target and we already have instructions, close current block
        if (jumpTargets.count(ins.address) && !currentBlock.instructions.empty())
        {
            currentBlock.endAddress = ins.address;
            currentBlock.fallthroughAddr = ins.address;
            fi.basicBlocks.push_back(currentBlock);

            currentBlock = BasicBlock();
            currentBlock.startAddress = ins.address;
            currentBlock.isTarget = true;
            edgeCount++;
        }

        currentBlock.instructions.push_back(ins);

        bool isCond = IsConditionalJump(ins.mnemonic);
        bool isUncond = IsUnconditionalJump(ins.mnemonic);
        bool isRet = IsReturn(ins.mnemonic);

        if (isCond || isUncond || isRet)
        {
            currentBlock.endAddress = ins.address + ins.size;
            currentBlock.isTerminal = isRet;

            if (isCond)
            {
                currentBlock.branchAddr = ins.targetAddress;
                if (i + 1 < insts.size())
                    currentBlock.fallthroughAddr = insts[i + 1].address;
                edgeCount += 2;
            }
            else if (isUncond)
            {
                currentBlock.branchAddr = ins.targetAddress;
                currentBlock.fallthroughAddr = 0;
                edgeCount += 1;
            }
            else if (isRet)
            {
                currentBlock.fallthroughAddr = 0;
                currentBlock.branchAddr = 0;
            }

            fi.basicBlocks.push_back(currentBlock);
            currentBlock = BasicBlock();
            if (i + 1 < insts.size())
                currentBlock.startAddress = insts[i + 1].address;
        }
    }

    if (!currentBlock.instructions.empty())
    {
        currentBlock.endAddress = currentBlock.instructions.back().address + currentBlock.instructions.back().size;
        fi.basicBlocks.push_back(currentBlock);
    }

    // V(G) = E - N + 2P
    int numBlocks = (int)fi.basicBlocks.size();
    int complexity = edgeCount - numBlocks + 2;
    fi.cyclomaticComplexity = (complexity > 1) ? complexity : 1;

    return fi;
}

std::string FunctionAnalyzer::GeneratePseudocode(const FunctionInfo& func, bool is64Bit) const
{
    std::ostringstream ss;
    ss << "// ============================================================================\n";
    ss << "// KYV HEX-RAYS PSEUDOCODE DECOMPILER\n";
    ss << "// Function: " << func.name << " | Address: " << helpers::FormatAddress(func.startAddress, is64Bit) << "\n";
    ss << "// Size: " << func.size << " bytes | Basic Blocks: " << func.basicBlocks.size() << " | Complexity V(G): " << func.cyclomaticComplexity << "\n";
    ss << "// Calling Convention: " << func.callingConvention << "\n";
    ss << "// ============================================================================\n\n";

    if (is64Bit)
    {
        ss << "int64_t " << func.name << "(int64_t rcx_arg, int64_t rdx_arg, int64_t r8_arg, int64_t r9_arg)\n{\n";
        ss << "    int64_t var_10 = rcx_arg;  // Shadow stack / fastcall arg 1\n";
        ss << "    int64_t var_18 = rdx_arg;  // Shadow stack / fastcall arg 2\n";
        ss << "    int64_t var_20 = r8_arg;   // Shadow stack / fastcall arg 3\n";
        ss << "    int64_t var_28 = r9_arg;   // Shadow stack / fastcall arg 4\n";
        ss << "    int64_t rax_result = 0;\n\n";
    }
    else
    {
        ss << "int32_t __stdcall " << func.name << "(int32_t arg1, int32_t arg2, int32_t arg3)\n{\n";
        ss << "    int32_t eax_result = 0;\n\n";
    }

    if (func.basicBlocks.empty())
    {
        ss << "    // [Unanalyzed or empty basic block]\n";
        ss << "    return " << (is64Bit ? "rax_result" : "eax_result") << ";\n}\n";
        return ss.str();
    }

    for (size_t bidx = 0; bidx < func.basicBlocks.size(); ++bidx)
    {
        const auto& bb = func.basicBlocks[bidx];
        ss << "loc_" << std::hex << std::uppercase << bb.startAddress << ":\n";
        ss << "    // --- Basic Block " << std::dec << bidx << " (" << helpers::FormatAddress(bb.startAddress, is64Bit) << " -> " << helpers::FormatAddress(bb.endAddress, is64Bit) << ") ---\n";

        for (const auto& ins : bb.instructions)
        {
            if (ins.isCall)
            {
                if (ins.targetAddress != 0)
                    ss << "    " << (is64Bit ? "rax_result" : "eax_result") << " = sub_" << std::hex << std::uppercase << ins.targetAddress << "(); // " << ins.operands << "\n";
                else
                    ss << "    " << (is64Bit ? "rax_result" : "eax_result") << " = indirect_call(" << ins.operands << ");\n";
            }
            else if (ins.mnemonic == "mov" || ins.mnemonic == "lea")
            {
                ss << "    " << ins.operands << "; // " << ins.mnemonic << "\n";
            }
            else if (ins.mnemonic == "xor" && ins.operands.size() >= 7 && ins.operands.substr(0, 3) == ins.operands.substr(5, 3))
            {
                ss << "    " << ins.operands.substr(0, 3) << " = 0;\n";
            }
            else if (IsConditionalJump(ins.mnemonic))
            {
                ss << "    if (" << ins.mnemonic << "_condition) {\n";
                ss << "        goto loc_" << std::hex << std::uppercase << ins.targetAddress << ";\n";
                if (bb.fallthroughAddr != 0)
                    ss << "    } else {\n        goto loc_" << std::hex << std::uppercase << bb.fallthroughAddr << ";\n";
                ss << "    }\n";
            }
            else if (IsUnconditionalJump(ins.mnemonic))
            {
                ss << "    goto loc_" << std::hex << std::uppercase << ins.targetAddress << ";\n";
            }
            else if (IsReturn(ins.mnemonic))
            {
                ss << "    return " << (is64Bit ? "rax_result" : "eax_result") << ";\n";
            }
            else if (ins.mnemonic != "nop" && ins.mnemonic != "push" && ins.mnemonic != "pop")
            {
                ss << "    // asm: " << ins.mnemonic << " " << ins.operands << "\n";
            }
        }
        ss << "\n";
    }

    ss << "}\n";
    return ss.str();
}

} // namespace kyv
