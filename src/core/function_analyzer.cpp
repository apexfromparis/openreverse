#include "function_analyzer.h"
#include "utils/helpers.h"
#include <sstream>
#include <algorithm>
#include <deque>
#include <limits>
#include <tuple>

namespace openreverse {

const BasicBlock* ControlFlowGraph::FindBlock(uint64_t startAddress) const
{
    auto it = std::lower_bound(basicBlocks.begin(), basicBlocks.end(), startAddress,
        [](const BasicBlock& block, uint64_t address) { return block.startAddress < address; });
    return it != basicBlocks.end() && it->startAddress == startAddress ? &*it : nullptr;
}

const BasicBlock* ControlFlowGraph::FindContainingBlock(uint64_t address) const
{
    auto it = std::upper_bound(basicBlocks.begin(), basicBlocks.end(), address,
        [](uint64_t value, const BasicBlock& block) { return value < block.startAddress; });
    if (it == basicBlocks.begin())
        return nullptr;
    --it;
    return address >= it->startAddress && address < it->endAddress ? &*it : nullptr;
}

bool FunctionAnalyzer::IsConditionalJump(const std::string& m)
{
    if (m == "loop" || m == "loope" || m == "loopne") return true;
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
                                                             size_t maxFunctions,
                                                             size_t maxDiscoveryInstructions)
{
    std::vector<FunctionInfo> functions;
    if (!data || dataSize < 16) return functions;

    std::set<uint64_t> discoveredAddrs;

    auto addCandidate = [&](uint64_t addr) {
        if (discoveredAddrs.count(addr)) return;
        if (addr < baseAddress || addr - baseAddress >= dataSize) return;
        discoveredAddrs.insert(addr);
    };

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

    // Bytewise scans cannot distinguish an opcode from 0xE8 inside an immediate.
    Disassembler decoder;
    if (maxDiscoveryInstructions != 0 && decoder.Init(is64Bit))
    {
        auto instructions = decoder.Disassemble(data, dataSize, baseAddress, maxDiscoveryInstructions);
        for (const auto& instruction : instructions)
        {
            if (discoveredAddrs.size() >= maxFunctions)
                break;
            if (!instruction.isCall || instruction.targetKind != InstructionTargetKind::Immediate)
                continue;
            const uint64_t target = instruction.targetAddress;
            if (target < baseAddress || target - baseAddress >= dataSize)
                continue;
            addCandidate(target);
        }
    }

    std::vector<uint64_t> sortedAddrs(discoveredAddrs.begin(), discoveredAddrs.end());
    for (size_t idx = 0; idx < sortedAddrs.size() && functions.size() < maxFunctions; ++idx)
    {
        uint64_t addr = sortedAddrs[idx];
        const uint64_t bufferEnd = dataSize > (std::numeric_limits<uint64_t>::max)() - baseAddress
            ? (std::numeric_limits<uint64_t>::max)()
            : baseAddress + dataSize;
        uint64_t nextAddr = (idx + 1 < sortedAddrs.size()) ? sortedAddrs[idx + 1] : bufferEnd;

        FunctionInfo fi;
        fi.startAddress = addr;
        fi.analysisLimit = std::min<uint64_t>(nextAddr, addr + std::min<uint64_t>(4096, bufferEnd - addr));
        fi.name = "sub_" + helpers::FormatAddress(addr, false);
        fi.source = FunctionSource::Heuristic;
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
        fi.analysisLimit = codeEnd - target > 4096 ? target + 4096 : codeEnd;
        fi.name = "sub_" + helpers::FormatAddress(target, is64Bit).substr(2);
        fi.source = FunctionSource::DirectCall;
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
        fi.name = "entry_point";
        if (fi.source != FunctionSource::RuntimeFunction && fi.source != FunctionSource::Symbol)
            fi.source = FunctionSource::EntryPoint;
    }

    for (size_t i = 0; i < exportAddresses.size(); ++i)
    {
        uint64_t addr = exportAddresses[i];
        if (addr == 0) continue;
        auto& fi = funcMap[addr];
        fi.startAddress = addr;
        fi.isExported = true;
        if (fi.source != FunctionSource::RuntimeFunction && fi.source != FunctionSource::Symbol)
            fi.source = FunctionSource::Export;
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

std::vector<FunctionInfo> FunctionAnalyzer::DiscoverFunctionsFromRuntimeFunctions(
    const std::vector<FunctionInfo>& existing, uint64_t imageBase,
    const std::vector<PERuntimeFunction>& runtimeFunctions, bool is64Bit)
{
    std::map<uint64_t, FunctionInfo> functions;
    for (const auto& function : existing)
        functions[function.startAddress] = function;

    for (const auto& runtime : runtimeFunctions)
    {
        if (runtime.beginRva >= runtime.endRva ||
            imageBase > (std::numeric_limits<uint64_t>::max)() - runtime.endRva)
            continue;
        const uint64_t start = imageBase + runtime.beginRva;
        auto& function = functions[start];
        function.startAddress = start;
        function.endAddress = imageBase + runtime.endRva;
        function.analysisLimit = function.endAddress;
        function.size = static_cast<size_t>(runtime.endRva - runtime.beginRva);
        function.boundaryKnown = true;
        function.source = FunctionSource::RuntimeFunction;
        if (function.name.empty())
            function.name = "sub_" + helpers::FormatAddress(start, is64Bit).substr(2);
    }

    std::vector<FunctionInfo> result;
    result.reserve(functions.size());
    for (auto& pair : functions)
        result.push_back(std::move(pair.second));
    return result;
}

FunctionInfo FunctionAnalyzer::AnalyzeFunction(const uint8_t* data, size_t dataSize,
                                               uint64_t funcAddress, uint64_t bufferBase,
                                               Disassembler& disasm, bool is64Bit,
                                               size_t maxBytes, size_t maxInstructions)
{
    FunctionInfo fi;
    fi.startAddress = funcAddress;
    fi.name = "sub_" + helpers::FormatAddress(funcAddress, is64Bit).substr(2);
    fi.source = FunctionSource::RecursiveTraversal;
    fi.cfg.entryAddress = funcAddress;

    if (!data || maxBytes == 0 || maxInstructions == 0 || funcAddress < bufferBase ||
        (funcAddress - bufferBase) >= dataSize)
        return fi;

    const size_t functionOffset = static_cast<size_t>(funcAddress - bufferBase);
    const size_t scanLength = std::min(maxBytes, dataSize - functionOffset);
    fi.analysisLimit = funcAddress + scanLength;
    const auto inRange = [&](uint64_t address) {
        return address >= funcAddress && address - funcAddress < scanLength;
    };

    std::map<uint64_t, Instruction> decoded;
    std::set<uint64_t> leaders{funcAddress};
    std::set<uint64_t> visitedLeaders;
    std::deque<uint64_t> pending{funcAddress};

    const auto queueLeader = [&](uint64_t address, std::deque<uint64_t>& queue) {
        if (!inRange(address))
            return;
        leaders.insert(address);
        if (visitedLeaders.count(address) == 0)
            queue.push_back(address);
    };

    while (!pending.empty() && decoded.size() < maxInstructions)
    {
        const uint64_t leader = pending.front();
        pending.pop_front();
        if (!inRange(leader) || !visitedLeaders.insert(leader).second)
            continue;

        uint64_t address = leader;
        while (inRange(address) && decoded.size() < maxInstructions)
        {
            if (address != leader && leaders.count(address) != 0)
                break;

            auto existing = decoded.find(address);
            if (existing != decoded.end())
            {
                leaders.insert(address);
                break;
            }

            auto nextDecoded = decoded.lower_bound(address);
            if (nextDecoded != decoded.begin())
            {
                const Instruction& previous = std::prev(nextDecoded)->second;
                if (address > previous.address && address - previous.address < previous.size)
                {
                    fi.cfg.complete = false;
                    break;
                }
            }

            const size_t bufferOffset = static_cast<size_t>(address - bufferBase);
            const size_t rangeRemaining = scanLength - static_cast<size_t>(address - funcAddress);
            const size_t available = std::min(dataSize - bufferOffset, rangeRemaining);
            Instruction instruction{};
            if (!disasm.DecodeInstruction(data + bufferOffset, available, address, instruction) ||
                instruction.address != address || instruction.size == 0 || instruction.size > available)
            {
                fi.cfg.complete = false;
                break;
            }
            if (nextDecoded != decoded.end() && nextDecoded->first - address < instruction.size)
            {
                fi.cfg.complete = false;
                break;
            }

            decoded.emplace(address, instruction);
            const bool isConditional = IsConditionalJump(instruction.mnemonic);
            const bool isUnconditional = IsUnconditionalJump(instruction.mnemonic);
            const bool isReturn = IsReturn(instruction.mnemonic);

            uint64_t nextAddress = 0;
            const bool hasNext = instruction.size <= (std::numeric_limits<uint64_t>::max)() - address;
            if (hasNext)
                nextAddress = address + instruction.size;

            if (isReturn)
                break;
            if (isConditional)
            {
                if (instruction.targetKind == InstructionTargetKind::Immediate)
                    queueLeader(instruction.targetAddress, pending);
                if (hasNext)
                    queueLeader(nextAddress, pending);
                break;
            }
            if (isUnconditional || instruction.isJump)
            {
                if (instruction.targetKind == InstructionTargetKind::Immediate)
                    queueLeader(instruction.targetAddress, pending);
                break;
            }
            if (!hasNext || !inRange(nextAddress))
            {
                fi.cfg.complete = false;
                break;
            }
            if (decoded.size() >= maxInstructions)
            {
                fi.cfg.complete = false;
                fi.cfg.instructionBudgetReached = true;
                break;
            }
            address = nextAddress;
        }
    }

    if (!pending.empty())
    {
        fi.cfg.complete = false;
        fi.cfg.instructionBudgetReached = true;
    }
    fi.cfg.decodedInstructionCount = decoded.size();
    if (decoded.empty())
        return fi;

    std::set<std::tuple<uint64_t, uint64_t, CFGEdgeType>> uniqueEdges;
    const auto addEdge = [&](uint64_t source, uint64_t target, CFGEdgeType type) {
        if (uniqueEdges.emplace(source, target, type).second)
            fi.cfg.edges.push_back({source, target, type});
    };

    for (uint64_t leader : leaders)
    {
        if (decoded.find(leader) == decoded.end())
            continue;

        BasicBlock block;
        block.startAddress = leader;
        uint64_t address = leader;
        while (true)
        {
            auto instructionIt = decoded.find(address);
            if (instructionIt == decoded.end())
                break;
            const Instruction& instruction = instructionIt->second;
            block.instructions.push_back(instruction);
            block.endAddress = instruction.address + instruction.size;

            if (IsReturn(instruction.mnemonic) || instruction.isJump)
                break;
            const uint64_t nextAddress = instruction.address + instruction.size;
            if (leaders.count(nextAddress) != 0 || decoded.find(nextAddress) == decoded.end())
                break;
            address = nextAddress;
        }

        if (block.instructions.empty())
            continue;
        fi.cfg.basicBlocks.push_back(std::move(block));
    }

    std::sort(fi.cfg.basicBlocks.begin(), fi.cfg.basicBlocks.end(),
        [](const BasicBlock& left, const BasicBlock& right) { return left.startAddress < right.startAddress; });

    for (auto& block : fi.cfg.basicBlocks)
    {
        const Instruction& terminator = block.instructions.back();
        const uint64_t nextAddress = terminator.address + terminator.size;
        if (IsReturn(terminator.mnemonic))
        {
            addEdge(block.startAddress, 0, CFGEdgeType::Return);
        }
        else if (IsConditionalJump(terminator.mnemonic))
        {
            if (terminator.targetKind == InstructionTargetKind::Immediate)
            {
                block.branchAddr = terminator.targetAddress;
                addEdge(block.startAddress, terminator.targetAddress, CFGEdgeType::ConditionalTrue);
            }
            if (inRange(nextAddress))
            {
                block.fallthroughAddr = nextAddress;
                addEdge(block.startAddress, nextAddress, CFGEdgeType::ConditionalFalse);
            }
        }
        else if (IsUnconditionalJump(terminator.mnemonic) || terminator.isJump)
        {
            if (terminator.targetKind == InstructionTargetKind::Immediate)
            {
                block.branchAddr = terminator.targetAddress;
                addEdge(block.startAddress, terminator.targetAddress, CFGEdgeType::Unconditional);
            }
        }
        else if (inRange(nextAddress) && leaders.count(nextAddress) != 0)
        {
            block.fallthroughAddr = nextAddress;
            addEdge(block.startAddress, nextAddress, CFGEdgeType::Fallthrough);
        }
    }

    for (const auto& edge : fi.cfg.edges)
    {
        auto source = std::lower_bound(fi.cfg.basicBlocks.begin(), fi.cfg.basicBlocks.end(), edge.source,
            [](const BasicBlock& block, uint64_t address) { return block.startAddress < address; });
        if (source != fi.cfg.basicBlocks.end() && source->startAddress == edge.source && edge.target != 0)
            source->successors.push_back(edge.target);

        auto target = std::lower_bound(fi.cfg.basicBlocks.begin(), fi.cfg.basicBlocks.end(), edge.target,
            [](const BasicBlock& block, uint64_t address) { return block.startAddress < address; });
        if (edge.target != 0 && target != fi.cfg.basicBlocks.end() && target->startAddress == edge.target)
            target->predecessors.push_back(edge.source);
    }

    int conditionalCount = 0;
    for (auto& block : fi.cfg.basicBlocks)
    {
        std::sort(block.successors.begin(), block.successors.end());
        block.successors.erase(std::unique(block.successors.begin(), block.successors.end()), block.successors.end());
        std::sort(block.predecessors.begin(), block.predecessors.end());
        block.predecessors.erase(std::unique(block.predecessors.begin(), block.predecessors.end()), block.predecessors.end());
        block.isTarget = block.startAddress == funcAddress || !block.predecessors.empty();

        bool hasInternalSuccessor = false;
        for (uint64_t successor : block.successors)
            if (fi.cfg.FindBlock(successor)) hasInternalSuccessor = true;
        block.isTerminal = !hasInternalSuccessor;

        const Instruction& last = block.instructions.back();
        if (IsConditionalJump(last.mnemonic))
            ++conditionalCount;
        fi.analyzedEndAddress = std::max(fi.analyzedEndAddress, block.endAddress);
    }

    for (const auto& pair : decoded)
    {
        const Instruction& instruction = pair.second;
        if (instruction.isCall && instruction.targetKind == InstructionTargetKind::Immediate)
            fi.callTargets.push_back(instruction.targetAddress);
    }

    fi.cyclomaticComplexity = 1 + conditionalCount;
    fi.analyzedSize = fi.analyzedEndAddress >= fi.startAddress
        ? static_cast<size_t>(fi.analyzedEndAddress - fi.startAddress) : 0;

    return fi;
}

std::string FunctionAnalyzer::GenerateAssemblySummary(const FunctionInfo& func, bool is64Bit) const
{
    std::ostringstream ss;
    ss << "OpenReverse control-flow assembly summary\n";
    ss << "Function: " << func.name << "\n";
    ss << "Address: " << helpers::FormatAddress(func.startAddress, is64Bit) << "\n";
    if (func.boundaryKnown)
        ss << "Boundary: " << helpers::FormatAddress(func.startAddress, is64Bit) << " - "
           << helpers::FormatAddress(func.endAddress, is64Bit) << " (" << func.size << " bytes)\n";
    else
        ss << "Boundary: unknown; analyzed extent " << func.analyzedSize << " bytes\n";
    ss << "Basic blocks: " << func.cfg.basicBlocks.size()
       << " | decoded instructions: " << func.cfg.decodedInstructionCount
       << " | V(G): " << func.cyclomaticComplexity << "\n";
    ss << "Every instruction below is decoded evidence; no source-level types or variables are inferred.\n\n";

    if (func.cfg.basicBlocks.empty())
    {
        ss << "No decoded basic blocks.\n";
        return ss.str();
    }

    for (size_t bidx = 0; bidx < func.cfg.basicBlocks.size(); ++bidx)
    {
        const auto& bb = func.cfg.basicBlocks[bidx];
        ss << "block_" << std::dec << bidx << " "
           << helpers::FormatAddress(bb.startAddress, is64Bit) << " - "
           << helpers::FormatAddress(bb.endAddress, is64Bit) << "\n";

        for (const auto& ins : bb.instructions)
        {
            ss << "  " << helpers::FormatAddress(ins.address, is64Bit) << "  "
               << ins.mnemonic;
            if (!ins.operands.empty()) ss << " " << ins.operands;
            ss << "\n";
        }
        if (!bb.successors.empty())
        {
            ss << "  successors:";
            for (const uint64_t successor : bb.successors)
                ss << " " << helpers::FormatAddress(successor, is64Bit);
            ss << "\n";
        }
        ss << "\n";
    }
    return ss.str();
}

} // namespace openreverse
