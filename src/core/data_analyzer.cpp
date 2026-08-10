#include "data_analyzer.h"

#include <algorithm>
#include <iterator>
#include <map>
#include <sstream>

namespace openreverse {

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
        candidate.sectionName = containingSection->name;
        candidate.accessSites.push_back(xref.fromAddress);
        if (xref.type == XRefType::ReadWrite)
        {
            ++candidate.readCount;
            ++candidate.writeCount;
        }
        else if (xref.type == XRefType::Write)
            ++candidate.writeCount;
        else if (xref.type == XRefType::Lea)
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
        candidate.confidence = std::min(0.99f, 0.55f + (candidate.writeCount ? 0.15f : 0.0f) +
            (candidate.readCount ? 0.10f : 0.0f) + (candidate.addressCount ? 0.05f : 0.0f) +
            0.02f * static_cast<float>(std::min<size_t>(references, 7)));
        result.push_back(std::move(candidate));
    }
    return result;
}

std::vector<FieldAccessCandidate> FindFieldAccesses(
    const std::vector<Instruction>& instructions, size_t maxCandidates)
{
    std::vector<FieldAccessCandidate> result;
    for (const auto& instruction : instructions)
    {
        for (const auto& memory : instruction.memoryOperands)
        {
            if (result.size() >= maxCandidates) return result;
            if (memory.ripRelative || memory.baseRegister.empty() || memory.displacement < 0 ||
                memory.displacement > 0x10000 || !memory.indexRegister.empty())
                continue;
            if (memory.baseRegister == "rsp" || memory.baseRegister == "rbp" ||
                memory.baseRegister == "esp" || memory.baseRegister == "ebp")
                continue;

            FieldAccessCandidate field;
            field.instructionAddress = instruction.address;
            field.offset = static_cast<uint64_t>(memory.displacement);
            field.operandSize = memory.size;
            field.baseRegister = memory.baseRegister;
            field.instructionText = instruction.mnemonic + " " + instruction.operands;
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
        uint64_t functionEnd = function->endAddress;
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
    std::map<GroupKey, std::map<uint64_t, StructureFieldCandidate>> grouped;
    for (const auto& access : fields)
    {
        if (access.functionAddress == 0) continue;
        auto& field = grouped[{access.functionAddress, access.baseRegister}][access.offset];
        field.offset = access.offset;
        field.size = std::max(field.size, access.operandSize);
        field.accessSites.push_back(access.instructionAddress);
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
        structure.baseRegister = key.second;
        std::ostringstream name;
        name << "struct_" << std::uppercase << std::hex << key.first << "_" << key.second;
        structure.name = name.str();
        for (auto& [offset, field] : fieldMap)
        {
            structure.estimatedSize = std::max<uint64_t>(structure.estimatedSize,
                offset + std::max<uint64_t>(field.size, 1));
            structure.fields.push_back(std::move(field));
        }
        structure.confidence = std::min(0.95f, 0.45f +
            0.08f * static_cast<float>(std::min<size_t>(structure.fields.size(), 6)));
        result.push_back(std::move(structure));
    }
    return result;
}

} // namespace openreverse
