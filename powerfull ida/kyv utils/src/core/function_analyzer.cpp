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

    std::set<uint64_t> discoveredAddrs;

    auto addCandidate = [&](uint64_t addr) {
        if (discoveredAddrs.count(addr)) return;
        if (addr < baseAddress || addr >= baseAddress + dataSize) return;
        discoveredAddrs.insert(addr);
    };

    // 1. Scan for x64 / x86 prologues, CET markers, and boundary transitions
    for (size_t i = 0; i + 4 < dataSize && discoveredAddrs.size() < maxFunctions; ++i)
    {
        bool isPrologue = false;
        if (is64Bit)
        {
            if (data[i] == 0x48 && data[i + 1] == 0x89 && data[i + 2] == 0x5C && data[i + 3] == 0x24)
                isPrologue = true; // mov [rsp+18h], rbx
            else if (data[i] == 0x48 && data[i + 1] == 0x83 && data[i + 2] == 0xEC && data[i + 3] >= 0x08)
                isPrologue = true; // sub rsp, imm8
            else if (data[i] == 0x48 && data[i + 1] == 0x81 && data[i + 2] == 0xEC)
                isPrologue = true; // sub rsp, imm32 (large stack frame)
            else if (i + 5 < dataSize && data[i] == 0x40 && data[i + 1] == 0x53 && data[i + 2] == 0x48 && data[i + 3] == 0x83 && data[i + 4] == 0xEC)
                isPrologue = true; // push rbx; sub rsp, imm8
            else if (data[i] == 0x55 && data[i + 1] == 0x48 && data[i + 2] == 0x8B && data[i + 3] == 0xEC)
                isPrologue = true; // push rbp; mov rbp, rsp
            else if (data[i] == 0x4C && data[i + 1] == 0x89 && (data[i + 2] == 0x44 || data[i + 2] == 0x4C) && data[i + 3] == 0x24)
                isPrologue = true; // mov [rsp+imm], r8/r9
            else if (data[i] == 0xF3 && data[i + 1] == 0x0F && data[i + 2] == 0x1E && data[i + 3] == 0xFA)
                isPrologue = true; // endbr64 (Intel CET)
            else if (data[i] == 0x40 && (data[i + 1] >= 0x50 && data[i + 1] <= 0x57) && data[i + 2] == 0x48 && data[i + 3] == 0x83 && data[i + 4] == 0xEC)
                isPrologue = true; // push r64; sub rsp, imm8
            else if ((data[i] == 0x53 || data[i] == 0x56 || data[i] == 0x57) && data[i + 1] == 0x48 && data[i + 2] == 0x83 && data[i + 3] == 0xEC)
                isPrologue = true; // push rbx/rsi/rdi; sub rsp, imm8
            else if (data[i] == 0x48 && data[i + 1] == 0x8B && data[i + 2] == 0xC4)
                isPrologue = true; // mov rax, rsp
        }
        else
        {
            if (data[i] == 0x55 && data[i + 1] == 0x8B && data[i + 2] == 0xEC)
                isPrologue = true; // push ebp; mov ebp, esp
            else if (data[i] == 0x83 && data[i + 1] == 0xEC && data[i + 2] >= 0x08)
                isPrologue = true; // sub esp, imm8
            else if (data[i] == 0x81 && data[i + 1] == 0xEC)
                isPrologue = true; // sub esp, imm32
            else if (data[i] == 0xF3 && data[i + 1] == 0x0F && data[i + 2] == 0x1E && data[i + 3] == 0xFB)
                isPrologue = true; // endbr32
            else if (i + 5 < dataSize && data[i] == 0x8B && data[i + 1] == 0xFF && data[i + 2] == 0x55 && data[i + 3] == 0x8B && data[i + 4] == 0xEC)
                isPrologue = true; // mov edi, edi; push ebp; mov ebp, esp (MSVC hotpatch)
        }

        // Boundary padding transition check: after CC (int 3) or C3 (ret) + CC/90 padding
        if (!isPrologue && i >= 2 && data[i] != 0xCC && data[i] != 0x90 && data[i] != 0x00)
        {
            if ((data[i - 1] == 0xCC && data[i - 2] == 0xCC) ||
                (data[i - 1] == 0xC3 && (i == 1 || data[i - 2] == 0xCC || data[i - 2] == 0x90)))
            {
                isPrologue = true;
            }
        }

        if (isPrologue)
        {
            addCandidate(baseAddress + i);
            i += 8;
        }
    }

    // 2. Structural discovery: scan for relative CALL instructions (0xE8) in executable code
    for (size_t i = 0; i + 5 <= dataSize && discoveredAddrs.size() < maxFunctions; ++i)
    {
        if (data[i] == 0xE8) // CALL rel32
        {
            int32_t rel32 = 0;
            std::memcpy(&rel32, data + i + 1, sizeof(int32_t));
            uint64_t target = baseAddress + i + 5 + rel32;
            if (target >= baseAddress && target < baseAddress + dataSize)
            {
                // Ensure target does not land in padding bytes
                size_t offset = (size_t)(target - baseAddress);
                if (data[offset] != 0xCC && data[offset] != 0x90 && data[offset] != 0x00)
                {
                    addCandidate(target);
                }
            }
        }
    }

    // 3. Construct sorted function list with smart boundary estimation
    std::vector<uint64_t> sortedAddrs(discoveredAddrs.begin(), discoveredAddrs.end());
    for (size_t idx = 0; idx < sortedAddrs.size() && functions.size() < maxFunctions; ++idx)
    {
        uint64_t addr = sortedAddrs[idx];
        uint64_t nextAddr = (idx + 1 < sortedAddrs.size()) ? sortedAddrs[idx + 1] : (baseAddress + dataSize);

        FunctionInfo fi;
        fi.startAddress = addr;
        fi.size = (size_t)std::min((uint64_t)2048, (uint64_t)(nextAddr - addr));
        fi.endAddress = addr + fi.size;
        fi.name = "sub_" + helpers::FormatAddress(addr, is64Bit).substr(2);
        fi.callingConvention = is64Bit ? "x64 fastcall (RCX, RDX, R8, R9)" : "x86 stdcall / cdecl";
        functions.push_back(fi);
    }

    return functions;
}

std::vector<FunctionInfo> FunctionAnalyzer::DiscoverFunctionsFromXRefs(const std::vector<FunctionInfo>& existing,
                                                                     const std::vector<uint64_t>& callTargets,
                                                                     uint64_t codeStart, uint64_t codeEnd, bool is64Bit,
                                                                     size_t maxFunctions)
{
    std::set<uint64_t> known;
    std::vector<FunctionInfo> out = existing;
    for (const auto& f : existing)
        known.insert(f.startAddress);

    for (uint64_t target : callTargets)
    {
        if (out.size() >= maxFunctions) break;
        if (target < codeStart || target >= codeEnd) continue;
        if (known.count(target)) continue;

        known.insert(target);
        FunctionInfo fi;
        fi.startAddress = target;
        fi.endAddress = target + 128;
        fi.size = 128;
        fi.name = "sub_" + helpers::FormatAddress(target, is64Bit).substr(2);
        fi.callingConvention = is64Bit ? "x64 fastcall" : "stdcall / cdecl";
        out.push_back(fi);
    }

    std::sort(out.begin(), out.end(), [](const FunctionInfo& a, const FunctionInfo& b) {
        return a.startAddress < b.startAddress;
    });
    return out;
}

std::vector<FunctionInfo> FunctionAnalyzer::DiscoverFunctionsFromPE(const std::vector<FunctionInfo>& existing,
                                                                  uint64_t entryPoint,
                                                                  const std::vector<uint64_t>& exportAddresses,
                                                                  bool is64Bit)
{
    std::map<uint64_t, FunctionInfo> funcMap;
    for (const auto& f : existing)
        funcMap[f.startAddress] = f;

    if (entryPoint != 0)
    {
        auto& fi = funcMap[entryPoint];
        fi.startAddress = entryPoint;
        if (fi.size == 0) { fi.size = 128; fi.endAddress = entryPoint + 128; }
        fi.name = "entry_point";
        fi.callingConvention = is64Bit ? "x64 fastcall" : "stdcall / cdecl";
    }

    for (size_t i = 0; i < exportAddresses.size(); ++i)
    {
        uint64_t addr = exportAddresses[i];
        if (addr == 0) continue;
        auto& fi = funcMap[addr];
        fi.startAddress = addr;
        if (fi.size == 0) { fi.size = 128; fi.endAddress = addr + 128; }
        fi.isExported = true;
        if (fi.name.empty() || fi.name.rfind("sub_", 0) == 0)
            fi.name = "Export_" + helpers::FormatAddress(addr, is64Bit).substr(2);
    }

    std::vector<FunctionInfo> out;
    for (const auto& pair : funcMap)
        out.push_back(pair.second);

    std::sort(out.begin(), out.end(), [](const FunctionInfo& a, const FunctionInfo& b) {
        return a.startAddress < b.startAddress;
    });
    return out;
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
