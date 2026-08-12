#include "data_analyzer.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>

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
};

bool AddSigned(int64_t left, int64_t right, int64_t& result)
{
    if ((right > 0 && left > (std::numeric_limits<int64_t>::max)() - right) ||
        (right < 0 && left < (std::numeric_limits<int64_t>::min)() - right))
        return false;
    result = left + right;
    return true;
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
    std::unordered_map<std::string, RegisterOrigin> origins;
    origins["rcx"] = {RegisterOriginKind::Argument, "rcx", 1, 0};
    origins["rdx"] = {RegisterOriginKind::Argument, "rdx", 2, 0};
    origins["r8"] = {RegisterOriginKind::Argument, "r8", 3, 0};
    origins["r9"] = {RegisterOriginKind::Argument, "r9", 4, 0};

    for (const auto& instruction : instructions)
    {
        for (const auto& memory : instruction.memoryOperands)
        {
            if (result.size() >= maxCandidates) return result;
            if (memory.ripRelative || memory.baseRegister.empty())
                continue;

            const std::string base = CanonicalRegister(memory.baseRegister);
            const auto origin = origins.find(base);
            const bool stackBase = base == "rsp" || base == "rbp";
            if (stackBase && (origin == origins.end() || origin->second.kind == RegisterOriginKind::StackLocal))
                continue;

            int64_t displacement = memory.displacement;
            if (origin != origins.end() &&
                !AddSigned(displacement, origin->second.adjustment, displacement))
                continue;
            if (displacement < -0x10000 || displacement > 0x10000)
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
            if (origin != origins.end())
            {
                field.originKind = origin->second.kind;
                field.originRegister = origin->second.root;
                field.argumentIndex = origin->second.argumentIndex;
                field.originAdjustment = origin->second.adjustment;
            }
            if (instruction.mnemonic == "lea")
                field.access = DataAccessType::Address;
            else if (memory.read && memory.write)
                field.access = DataAccessType::ReadWrite;
            else if (memory.write)
                field.access = DataAccessType::Write;
            else
                field.access = DataAccessType::Read;
            result.push_back(std::move(field));
        }

        std::string propagatedDestination;
        if ((instruction.mnemonic == "mov" || instruction.mnemonic == "movzx" ||
             instruction.mnemonic == "movsxd") && instruction.decodedOperands.size() >= 2 &&
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
                copied.kind = RegisterOriginKind::RegisterCopy;
                origins[destination] = std::move(copied);
            }
            else
                origins.erase(destination);
            propagatedDestination = destination;
        }
        else if (instruction.mnemonic == "lea" && instruction.decodedOperands.size() >= 2 &&
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
                if (AddSigned(derived.adjustment, memory.displacement, adjustment))
                {
                    derived.adjustment = adjustment;
                    derived.kind = RegisterOriginKind::RegisterCopy;
                    origins[destination] = std::move(derived);
                }
                else
                    origins.erase(destination);
            }
            else if (source == "rsp" || source == "rbp")
                origins[destination] = {RegisterOriginKind::StackLocal, source, 0, memory.displacement};
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
        }
        if (instruction.isRet || FunctionAnalyzer::IsUnconditionalJump(instruction.mnemonic))
            origins.clear();
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
            : (!access.originRegister.empty() ? access.originRegister : access.baseRegister);
        const GroupKey key{access.functionAddress, context};
        representatives.emplace(key, &access);
        auto& field = grouped[key][access.offset];
        field.offset = access.offset;
        field.size = std::max(field.size, access.operandSize);
        field.accessSites.push_back(access.instructionAddress);
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
        if (fieldMap.size() < 2) continue;
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
            observations += field.readCount + field.writeCount + field.addressCount;
        structure.evidenceScore = static_cast<uint32_t>(std::min<size_t>(observations, 100000));
        structure.evidence = structure.argumentIndex != 0
            ? EvidenceLevel::Inferred : EvidenceLevel::Heuristic;
        result.push_back(std::move(structure));
    }
    return result;
}

} // namespace openreverse
