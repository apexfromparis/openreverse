#include "data_evidence.h"
#include "analysis/instruction_semantics.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <deque>

namespace openreverse {

namespace {

std::string CanonicalRegister(std::string name)
{
    static const std::map<std::string, std::string> aliases = {
        {"al", "rax"}, {"ah", "rax"}, {"ax", "rax"}, {"eax", "rax"},
        {"bl", "rbx"}, {"bh", "rbx"}, {"bx", "rbx"}, {"ebx", "rbx"},
        {"cl", "rcx"}, {"ch", "rcx"}, {"cx", "rcx"}, {"ecx", "rcx"},
        {"dl", "rdx"}, {"dh", "rdx"}, {"dx", "rdx"}, {"edx", "rdx"},
        {"sil", "rsi"}, {"si", "rsi"}, {"esi", "rsi"},
        {"dil", "rdi"}, {"di", "rdi"}, {"edi", "rdi"},
        {"bpl", "rbp"}, {"bp", "rbp"}, {"ebp", "rbp"},
        {"spl", "rsp"}, {"sp", "rsp"}, {"esp", "rsp"},
        {"r8b", "r8"}, {"r8w", "r8"}, {"r8d", "r8"},
        {"r9b", "r9"}, {"r9w", "r9"}, {"r9d", "r9"},
        {"r10b", "r10"}, {"r10w", "r10"}, {"r10d", "r10"},
        {"r11b", "r11"}, {"r11w", "r11"}, {"r11d", "r11"},
        {"r12b", "r12"}, {"r12w", "r12"}, {"r12d", "r12"},
        {"r13b", "r13"}, {"r13w", "r13"}, {"r13d", "r13"},
        {"r14b", "r14"}, {"r14w", "r14"}, {"r14d", "r14"},
        {"r15b", "r15"}, {"r15w", "r15"}, {"r15d", "r15"}
    };
    const auto alias = aliases.find(name);
    return alias == aliases.end() ? name : alias->second;
}

struct RegisterOrigin {
    RegisterOriginKind kind = RegisterOriginKind::Unknown;
    std::string root;
    uint8_t argumentIndex = 0;
    int64_t adjustment = 0;
    uint64_t originBlockAddress = 0;
    uint16_t propagationDepth = 0;
    uint16_t crossedBlocks = 0;
    uint64_t callInstructionAddress = 0;
    uint64_t callTargetAddress = 0;
};

using OriginState = std::map<std::string, RegisterOrigin>;

OriginState SeedArgumentOrigins(uint64_t blockAddress)
{
    OriginState origins;
    origins["rcx"] = {RegisterOriginKind::Argument, "rcx", 1, 0, blockAddress};
    origins["rdx"] = {RegisterOriginKind::Argument, "rdx", 2, 0, blockAddress};
    origins["r8"] = {RegisterOriginKind::Argument, "r8", 3, 0, blockAddress};
    origins["r9"] = {RegisterOriginKind::Argument, "r9", 4, 0, blockAddress};
    return origins;
}

bool SameOriginValue(const RegisterOrigin& left, const RegisterOrigin& right)
{
    return left.kind != RegisterOriginKind::Ambiguous &&
           right.kind != RegisterOriginKind::Ambiguous &&
           left.root == right.root && left.argumentIndex == right.argumentIndex &&
           left.adjustment == right.adjustment &&
           left.callInstructionAddress == right.callInstructionAddress &&
           left.callTargetAddress == right.callTargetAddress;
}

bool SameOriginState(const OriginState& left, const OriginState& right)
{
    if (left.size() != right.size()) return false;
    auto leftIt = left.begin();
    auto rightIt = right.begin();
    for (; leftIt != left.end(); ++leftIt, ++rightIt)
    {
        const auto& a = leftIt->second;
        const auto& b = rightIt->second;
        if (leftIt->first != rightIt->first || a.kind != b.kind || a.root != b.root ||
            a.argumentIndex != b.argumentIndex || a.adjustment != b.adjustment ||
            a.originBlockAddress != b.originBlockAddress)
            return false;
        if (a.callInstructionAddress != b.callInstructionAddress ||
            a.callTargetAddress != b.callTargetAddress)
            return false;
    }
    return true;
}

OriginState MergeOrigins(const std::vector<const OriginState*>& incoming)
{
    OriginState merged;
    std::set<std::string> registers;
    for (const auto* state : incoming)
        for (const auto& [name, origin] : *state)
            registers.insert(name);

    for (const auto& name : registers)
    {
        const RegisterOrigin* first = nullptr;
        bool ambiguous = false;
        uint16_t maximumDepth = 0;
        uint16_t maximumCrossedBlocks = 0;
        for (const auto* state : incoming)
        {
            const auto found = state->find(name);
            if (found == state->end())
            {
                ambiguous = true;
                continue;
            }
            if (!first)
                first = &found->second;
            else if (!SameOriginValue(*first, found->second))
                ambiguous = true;
            maximumDepth = std::max(maximumDepth, found->second.propagationDepth);
            maximumCrossedBlocks = std::max(maximumCrossedBlocks, found->second.crossedBlocks);
        }
        if (!first)
            continue;
        if (ambiguous || first->kind == RegisterOriginKind::Ambiguous)
        {
            RegisterOrigin value;
            value.kind = RegisterOriginKind::Ambiguous;
            value.propagationDepth = maximumDepth;
            value.crossedBlocks = maximumCrossedBlocks;
            merged[name] = std::move(value);
        }
        else
        {
            RegisterOrigin value = *first;
            value.propagationDepth = maximumDepth;
            value.crossedBlocks = maximumCrossedBlocks;
            merged[name] = std::move(value);
        }
    }
    return merged;
}

bool AddSigned(int64_t left, int64_t right, int64_t& result)
{
    if ((right > 0 && left > (std::numeric_limits<int64_t>::max)() - right) ||
        (right < 0 && left < (std::numeric_limits<int64_t>::min)() - right))
        return false;
    result = left + right;
    return true;
}

void ProcessInstructions(const std::vector<Instruction>& instructions, OriginState& origins,
                         uint64_t blockAddress, uint16_t predecessorCount,
                         std::vector<FieldAccessCandidate>* result, size_t maxCandidates)
{
    for (const auto& instruction : instructions)
    {
        if (result)
        {
            for (const auto& memory : instruction.memoryOperands)
            {
                if (result->size() >= maxCandidates) return;
                if (memory.ripRelative || memory.baseRegister.empty())
                    continue;

                const std::string base = CanonicalRegister(memory.baseRegister);
                const auto origin = origins.find(base);
                const bool stackBase = base == "rsp" || base == "rbp";
                if (stackBase && (origin == origins.end() ||
                    origin->second.kind == RegisterOriginKind::StackLocal))
                    continue;

                int64_t displacement = memory.displacement;
                if (origin != origins.end() &&
                    origin->second.kind != RegisterOriginKind::Ambiguous &&
                    !AddSigned(displacement, origin->second.adjustment, displacement))
                    continue;
                if (displacement < -0x100000 || displacement > 0x100000)
                    continue;

                FieldAccessCandidate field;
                field.instructionAddress = instruction.address;
                field.displacement = displacement;
                field.offset = displacement;
                field.operandSize = memory.size;
                field.operandIndex = memory.operandIndex;
                field.baseRegister = memory.baseRegister;
                field.indexRegister = memory.indexRegister;
                field.scale = memory.scale;
                field.instructionText = instruction.mnemonic + " " + instruction.operands;
                field.sourceBlockAddress = blockAddress;
                field.predecessorCount = predecessorCount;
                if (origin != origins.end())
                {
                    field.originKind = origin->second.kind;
                    field.originRegister = origin->second.root;
                    field.argumentIndex = origin->second.argumentIndex;
                    field.originAdjustment = origin->second.adjustment;
                    field.originBlockAddress = origin->second.originBlockAddress;
                    field.callInstructionAddress = origin->second.callInstructionAddress;
                    field.callTargetAddress = origin->second.callTargetAddress;
                    field.propagationDepth = origin->second.propagationDepth;
                    field.interBlock = origin->second.crossedBlocks != 0;
                    field.mergeAmbiguous = origin->second.kind == RegisterOriginKind::Ambiguous;
                }
                if (IsAddressCalculationInstruction(instruction))
                    field.access = DataAccessType::Address;
                else if (memory.read && memory.write)
                    field.access = DataAccessType::ReadWrite;
                else if (memory.write)
                    field.access = DataAccessType::Write;
                else
                    field.access = DataAccessType::Read;
                result->push_back(std::move(field));
            }
        }

        std::string propagatedDestination;
        if (IsMovePropagationInstruction(instruction) && instruction.decodedOperands.size() >= 2 &&
            instruction.decodedOperands[0].type == OperandType::Register &&
            instruction.decodedOperands[1].type == OperandType::Register)
        {
            const std::string destination = CanonicalRegister(
                instruction.decodedOperands[0].registerName);
            const std::string source = CanonicalRegister(instruction.decodedOperands[1].registerName);
            const auto sourceOrigin = origins.find(source);
            if (sourceOrigin != origins.end())
            {
                RegisterOrigin copied = sourceOrigin->second;
                if (copied.kind != RegisterOriginKind::Ambiguous &&
                    copied.kind != RegisterOriginKind::CallReturn)
                    copied.kind = RegisterOriginKind::RegisterCopy;
                if (copied.propagationDepth != (std::numeric_limits<uint16_t>::max)())
                    ++copied.propagationDepth;
                origins[destination] = std::move(copied);
            }
            else
                origins.erase(destination);
            propagatedDestination = destination;
        }
        else if (IsAddressCalculationInstruction(instruction) &&
                 instruction.decodedOperands.size() >= 2 &&
                 instruction.decodedOperands[0].type == OperandType::Register &&
                 instruction.decodedOperands[1].type == OperandType::Memory &&
                 instruction.decodedOperands[1].memory.indexRegister.empty())
        {
            const std::string destination = CanonicalRegister(
                instruction.decodedOperands[0].registerName);
            const auto& memory = instruction.decodedOperands[1].memory;
            const std::string source = CanonicalRegister(memory.baseRegister);
            const auto sourceOrigin = origins.find(source);
            if (sourceOrigin != origins.end())
            {
                RegisterOrigin derived = sourceOrigin->second;
                int64_t adjustment = 0;
                if (derived.kind == RegisterOriginKind::Ambiguous)
                    origins[destination] = derived;
                else if (AddSigned(derived.adjustment, memory.displacement, adjustment))
                {
                    derived.adjustment = adjustment;
                    if (derived.kind != RegisterOriginKind::CallReturn)
                        derived.kind = RegisterOriginKind::RegisterCopy;
                    if (derived.propagationDepth != (std::numeric_limits<uint16_t>::max)())
                        ++derived.propagationDepth;
                    origins[destination] = std::move(derived);
                }
                else
                    origins.erase(destination);
            }
            else if (source == "rsp" || source == "rbp")
            {
                RegisterOrigin local;
                local.kind = RegisterOriginKind::StackLocal;
                local.root = source;
                local.adjustment = memory.displacement;
                local.originBlockAddress = blockAddress;
                local.propagationDepth = 1;
                origins[destination] = std::move(local);
            }
            else
                origins.erase(destination);
            propagatedDestination = destination;
        }

        for (const auto& written : instruction.registersWritten)
        {
            const std::string destination = CanonicalRegister(written);
            if (destination != propagatedDestination)
                origins.erase(destination);
        }
        if (instruction.isCall)
        {
            for (const char* volatileRegister : {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"})
                origins.erase(volatileRegister);
            if (instruction.targetKind == InstructionTargetKind::Immediate)
            {
                RegisterOrigin returned;
                returned.kind = RegisterOriginKind::CallReturn;
                returned.root = "call_return";
                returned.originBlockAddress = blockAddress;
                returned.propagationDepth = 1;
                returned.callInstructionAddress = instruction.address;
                returned.callTargetAddress = instruction.targetAddress;
                origins["rax"] = std::move(returned);
            }
        }
    }
}

} // namespace

std::vector<GlobalCandidate> FindGlobalCandidates(const ModuleInfo& module, const PEInfo& pe,
                                                  const std::vector<XRefEntry>& xrefs)
{
    std::map<uint64_t, GlobalCandidate> candidates;
    for (const auto& xref : xrefs)
    {
        if (xref.type == XRefType::Call || xref.type == XRefType::Jump || xref.toAddress < module.baseAddress)
            continue;
        const uint64_t rva = xref.toAddress - module.baseAddress;

        const PESectionInfo* containingSection = nullptr;
        for (const auto& section : pe.sections)
        {
            const uint64_t span = std::max<uint64_t>(section.virtualSize, section.rawDataSize);
            if (rva >= section.virtualAddress && rva - section.virtualAddress < span)
            {
                containingSection = &section;
                break;
            }
        }
        if (!containingSection || (containingSection->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            continue;

        auto& candidate = candidates[xref.toAddress];
        candidate.address = xref.toAddress;
        candidate.moduleOffset = rva;
        candidate.rva = rva;
        candidate.sectionName = containingSection->name;
        candidate.kind = (containingSection->characteristics & IMAGE_SCN_MEM_WRITE) != 0
            ? GlobalKind::WritableData : GlobalKind::ReadonlyData;
        candidate.accessSites.push_back(xref.fromAddress);
        candidate.xrefs.push_back(xref);
        if (xref.functionAddress != 0 &&
            std::find(candidate.sourceFunctions.begin(), candidate.sourceFunctions.end(),
                      xref.functionAddress) == candidate.sourceFunctions.end())
            candidate.sourceFunctions.push_back(xref.functionAddress);
        if (xref.operandSize != 0 &&
            std::find(candidate.operandWidths.begin(), candidate.operandWidths.end(),
                      xref.operandSize) == candidate.operandWidths.end())
            candidate.operandWidths.push_back(xref.operandSize);
        if (xref.type == XRefType::ReadWrite)
        {
            ++candidate.readCount;
            ++candidate.writeCount;
        }
        else if (xref.type == XRefType::Write)
            ++candidate.writeCount;
        else if (xref.type == XRefType::Address)
            ++candidate.addressCount;
        else
            ++candidate.readCount;
    }

    std::vector<GlobalCandidate> result;
    result.reserve(candidates.size());
    for (auto& [address, candidate] : candidates)
    {
        std::ostringstream name;
        name << "global_" << std::uppercase << std::hex << candidate.moduleOffset;
        candidate.name = name.str();
        const size_t references = candidate.readCount + candidate.writeCount + candidate.addressCount;
        candidate.evidenceScore = static_cast<uint32_t>(std::min<size_t>(references, 100000));
        candidate.evidence = EvidenceLevel::Inferred;
        result.push_back(std::move(candidate));
    }
    return result;
}

std::vector<FieldAccessCandidate> FindFieldAccesses(
    const std::vector<Instruction>& instructions, size_t maxCandidates)
{
    std::vector<FieldAccessCandidate> result;
    OriginState origins = SeedArgumentOrigins(instructions.empty() ? 0 : instructions.front().address);
    ProcessInstructions(instructions, origins, instructions.empty() ? 0 : instructions.front().address,
                        0, &result, maxCandidates);
    return result;
}

std::vector<FieldAccessCandidate> FindFieldAccesses(
    const FunctionInfo& function, size_t maxCandidates)
{
    std::vector<FieldAccessCandidate> result;
    if (function.cfg.basicBlocks.empty() || maxCandidates == 0)
        return result;

    std::map<uint64_t, OriginState> inStates;
    std::map<uint64_t, OriginState> outStates;
    std::deque<uint64_t> worklist{function.cfg.entryAddress};
    std::set<uint64_t> queued{function.cfg.entryAddress};
    const OriginState entrySeed = SeedArgumentOrigins(function.cfg.entryAddress);

    size_t iterations = 0;
    const size_t iterationLimit = std::max<size_t>(
        function.cfg.basicBlocks.size() * 16, function.cfg.basicBlocks.size());
    while (!worklist.empty() && iterations++ < iterationLimit)
    {
        const uint64_t address = worklist.front();
        worklist.pop_front();
        queued.erase(address);
        const BasicBlock* block = function.cfg.FindBlock(address);
        if (!block) continue;

        std::vector<const OriginState*> incoming;
        if (address == function.cfg.entryAddress)
            incoming.push_back(&entrySeed);
        for (uint64_t predecessor : block->predecessors)
        {
            const auto found = outStates.find(predecessor);
            if (found != outStates.end())
                incoming.push_back(&found->second);
        }
        if (incoming.empty())
            continue;

        OriginState merged = MergeOrigins(incoming);
        if (address != function.cfg.entryAddress)
        {
            for (auto& [name, origin] : merged)
                origin.crossedBlocks = 1;
        }
        const auto existingIn = inStates.find(address);
        const bool inputChanged = existingIn == inStates.end() ||
                                  !SameOriginState(existingIn->second, merged);
        if (inputChanged)
            inStates[address] = merged;

        OriginState output = std::move(merged);
        ProcessInstructions(block->instructions, output, block->startAddress,
                            static_cast<uint16_t>(std::min<size_t>(
                                block->predecessors.size(),
                                (std::numeric_limits<uint16_t>::max)())),
                            nullptr, 0);
        const auto existingOut = outStates.find(address);
        if (existingOut != outStates.end() && SameOriginState(existingOut->second, output))
            continue;
        outStates[address] = std::move(output);
        for (uint64_t successor : block->successors)
        {
            if (!function.cfg.FindBlock(successor) || !queued.insert(successor).second)
                continue;
            worklist.push_back(successor);
        }
    }

    for (const auto& block : function.cfg.basicBlocks)
    {
        const auto state = inStates.find(block.startAddress);
        if (state == inStates.end()) continue;
        OriginState origins = state->second;
        ProcessInstructions(block.instructions, origins, block.startAddress,
                            static_cast<uint16_t>(std::min<size_t>(
                                block.predecessors.size(),
                                (std::numeric_limits<uint16_t>::max)())),
                            &result, maxCandidates);
        for (auto& field : result)
            if (field.functionAddress == 0)
                field.functionAddress = function.startAddress;
        if (result.size() >= maxCandidates) break;
    }
    return result;
}

void AssignFieldFunctions(std::vector<FieldAccessCandidate>& fields,
                          const std::vector<FunctionInfo>& functions)
{
    if (functions.empty()) return;
    std::vector<const FunctionInfo*> sortedFunctions;
    sortedFunctions.reserve(functions.size());
    for (const auto& function : functions) sortedFunctions.push_back(&function);
    std::sort(sortedFunctions.begin(), sortedFunctions.end(), [](const auto* left, const auto* right) {
        return left->startAddress < right->startAddress;
    });

    for (auto& field : fields)
    {
        const auto next = std::upper_bound(sortedFunctions.begin(), sortedFunctions.end(),
            field.instructionAddress, [](uint64_t address, const FunctionInfo* function) {
                return address < function->startAddress;
            });
        if (next == sortedFunctions.begin()) continue;
        const auto* function = *std::prev(next);
        uint64_t functionEnd = function->boundaryKnown ? function->endAddress : function->analysisLimit;
        if (functionEnd <= function->startAddress && next != sortedFunctions.end())
            functionEnd = (*next)->startAddress;
        if (functionEnd > function->startAddress && field.instructionAddress >= functionEnd)
            continue;
        field.functionAddress = function->startAddress;
    }
}

std::vector<StructureCandidate> InferStructures(const std::vector<FieldAccessCandidate>& fields)
{
    using GroupKey = std::pair<uint64_t, std::string>;
    std::map<GroupKey, std::map<int64_t, StructureFieldCandidate>> grouped;
    std::map<GroupKey, const FieldAccessCandidate*> representatives;
    for (const auto& access : fields)
    {
        if (access.functionAddress == 0) continue;
        const std::string context = access.argumentIndex != 0
            ? "arg" + std::to_string(access.argumentIndex)
            : (access.mergeAmbiguous ? "ambiguous_" + access.baseRegister :
               (!access.originRegister.empty() ? access.originRegister : access.baseRegister));
        const GroupKey key{access.functionAddress, context};
        representatives.emplace(key, &access);
        auto& field = grouped[key][access.offset];
        field.offset = access.offset;
        field.size = std::max(field.size, access.operandSize);
        field.accessSites.push_back(access.instructionAddress);
        if (access.interBlock) ++field.interBlockCount;
        if (access.mergeAmbiguous) ++field.ambiguousOriginCount;
        field.maxPropagationDepth = std::max(field.maxPropagationDepth, access.propagationDepth);
        if (std::find(field.baseRegisters.begin(), field.baseRegisters.end(), access.baseRegister) ==
            field.baseRegisters.end())
            field.baseRegisters.push_back(access.baseRegister);
        if (std::find(field.observingFunctions.begin(), field.observingFunctions.end(),
                      access.functionAddress) == field.observingFunctions.end())
            field.observingFunctions.push_back(access.functionAddress);
        if (access.access == DataAccessType::Write || access.access == DataAccessType::ReadWrite)
            ++field.writeCount;
        if (access.access == DataAccessType::Read || access.access == DataAccessType::ReadWrite)
            ++field.readCount;
        if (access.access == DataAccessType::Address)
            ++field.addressCount;
    }

    std::vector<StructureCandidate> result;
    for (auto& [key, fieldMap] : grouped)
    {
        if (fieldMap.empty()) continue;
        StructureCandidate structure;
        structure.functionAddress = key.first;
        structure.baseRegister = key.second.rfind("arg", 0) == 0 ? "Arg" + key.second.substr(3) : key.second;
        const auto representative = representatives.find(key);
        if (representative != representatives.end())
        {
            structure.originKind = representative->second->originKind;
            structure.argumentIndex = representative->second->argumentIndex;
        }
        std::ostringstream name;
        name << "struct_" << std::uppercase << std::hex << key.first << "_" << key.second;
        structure.name = name.str();
        for (auto& [offset, field] : fieldMap)
        {
            if (offset >= 0)
                structure.estimatedSize = std::max<uint64_t>(structure.estimatedSize,
                    static_cast<uint64_t>(offset) + std::max<uint64_t>(field.size, 1));
            structure.fields.push_back(std::move(field));
        }
        size_t observations = 0;
        for (const auto& field : structure.fields)
        {
            observations += field.readCount + field.writeCount + field.addressCount;
            structure.interBlockObservationCount += field.interBlockCount;
            structure.ambiguousOriginCount += field.ambiguousOriginCount;
            structure.maxPropagationDepth = std::max(
                structure.maxPropagationDepth, field.maxPropagationDepth);
        }
        structure.evidenceScore = static_cast<uint32_t>(std::min<size_t>(observations, 100000));
        structure.evidence = structure.ambiguousOriginCount != 0
            ? EvidenceLevel::Partial
            : structure.argumentIndex != 0 ? EvidenceLevel::Inferred : EvidenceLevel::Heuristic;
        result.push_back(std::move(structure));
    }
    return result;
}

} // namespace openreverse
