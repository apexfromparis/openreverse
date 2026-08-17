#include "xref_scanner.h"
#include "core/instruction_semantics.h"
#include "core/function_analyzer.h"
#include "utils/helpers.h"
#include <algorithm>
#include <set>
#include <tuple>
#include <utility>

namespace openreverse {

void XRefScanner::Clear()
{
    entries_.clear();
    toIndex_.clear();
    fromIndex_.clear();
}

void XRefScanner::ReplaceEntries(std::vector<XRefEntry> entries)
{
    Clear();
    entries_ = std::move(entries);
    for (size_t index = 0; index < entries_.size(); ++index)
    {
        toIndex_[entries_[index].toAddress].push_back(index);
        fromIndex_[entries_[index].fromAddress].push_back(index);
    }
}

void XRefScanner::ScanBuffer(const uint8_t* data, size_t dataSize, uint64_t baseAddress,
                             const std::string& moduleName, Disassembler& disasm, bool)
{
    if (!data || dataSize == 0) return;

    constexpr size_t kMaxIndexedXRefs = 500000;
    constexpr size_t kMaxInstructionsPerScan = 250000;
    if (entries_.size() >= kMaxIndexedXRefs)
        return;
    const size_t instructionLimit = std::min(kMaxInstructionsPerScan, kMaxIndexedXRefs - entries_.size());
    auto insts = disasm.Disassemble(data, dataSize, baseAddress, instructionLimit);
    ScanInstructions(insts, moduleName);
}

void XRefScanner::ScanInstructions(const std::vector<Instruction>& insts, const std::string& moduleName)
{
    constexpr size_t kMaxIndexedXRefs = 500000;

    for (const auto& ins : insts)
    {
        std::set<std::tuple<uint64_t, XRefType, uint8_t>> emitted;
        const auto emit = [&](uint64_t target, XRefType type, uint8_t operandIndex, uint8_t operandSize) {
            if (target == 0 || entries_.size() >= kMaxIndexedXRefs ||
                !emitted.emplace(target, type, operandIndex).second)
                return;
            size_t idx = entries_.size();
            XRefEntry entry;
            entry.fromAddress = ins.address;
            entry.toAddress = target;
            entry.type = type;
            entry.operandIndex = operandIndex;
            entry.operandSize = operandSize;
            entry.instructionText = ins.mnemonic + " " + ins.operands;
            entry.moduleName = moduleName;
            entries_.push_back(entry);
            toIndex_[target].push_back(idx);
            fromIndex_[ins.address].push_back(idx);
        };

        for (const auto& operand : ins.decodedOperands)
        {
            if (operand.type == OperandType::Immediate && (ins.isCall || ins.isJump))
            {
                emit(static_cast<uint64_t>(operand.immediate),
                     ins.isCall ? XRefType::Call : XRefType::Jump,
                     operand.index, operand.size);
            }
            else if (operand.type == OperandType::Memory && operand.memory.resolved)
            {
                XRefType type = XRefType::Data;
                if (IsAddressCalculationInstruction(ins))
                    type = XRefType::Address;
                else if (operand.read && operand.write)
                    type = XRefType::ReadWrite;
                else if (operand.write)
                    type = XRefType::Write;
                else if (operand.read)
                    type = XRefType::Read;
                emit(operand.memory.resolvedAddress, type, operand.index, operand.size);
            }
        }

        if (emitted.empty() && ins.targetAddress != 0 && (ins.isCall || ins.isJump))
            emit(ins.targetAddress, ins.isCall ? XRefType::Call : XRefType::Jump, 0, 0);
        if (entries_.size() >= kMaxIndexedXRefs)
            break;
    }
}

void AssignXRefFunctions(std::vector<XRefEntry>& xrefs,
                         const std::vector<FunctionInfo>& functions)
{
    std::vector<const FunctionInfo*> sorted;
    sorted.reserve(functions.size());
    for (const auto& function : functions)
        sorted.push_back(&function);
    std::sort(sorted.begin(), sorted.end(), [](const auto* left, const auto* right) {
        return left->startAddress < right->startAddress;
    });

    for (auto& xref : xrefs)
    {
        const auto next = std::upper_bound(sorted.begin(), sorted.end(), xref.fromAddress,
            [](uint64_t address, const FunctionInfo* function) {
                return address < function->startAddress;
            });
        if (next == sorted.begin())
            continue;
        const auto* function = *std::prev(next);
        uint64_t limit = function->boundaryKnown ? function->endAddress : function->analysisLimit;
        if (limit == 0 && next != sorted.end())
            limit = (*next)->startAddress;
        if (limit == 0 || xref.fromAddress < limit)
            xref.functionAddress = function->startAddress;
    }
}

std::vector<XRefEntry> XRefScanner::FindXRefsTo(uint64_t targetAddress) const
{
    std::vector<XRefEntry> results;
    auto it = toIndex_.find(targetAddress);
    if (it != toIndex_.end())
    {
        for (size_t idx : it->second)
        {
            if (idx < entries_.size())
                results.push_back(entries_[idx]);
        }
    }
    return results;
}

std::vector<XRefEntry> XRefScanner::FindXRefsFrom(uint64_t sourceAddress) const
{
    std::vector<XRefEntry> results;
    auto it = fromIndex_.find(sourceAddress);
    if (it != fromIndex_.end())
    {
        for (size_t idx : it->second)
        {
            if (idx < entries_.size())
                results.push_back(entries_[idx]);
        }
    }
    return results;
}

std::vector<XRefEntry> XRefScanner::SearchXRefsByText(const std::string& query) const
{
    std::vector<XRefEntry> results;
    if (query.empty()) return results;
    std::string lowerQ = helpers::ToLower(query);

    for (const auto& entry : entries_)
    {
        if (helpers::ToLower(entry.instructionText).find(lowerQ) != std::string::npos ||
            helpers::ToLower(helpers::FormatAddress(entry.toAddress)).find(lowerQ) != std::string::npos ||
            helpers::ToLower(helpers::FormatAddress(entry.fromAddress)).find(lowerQ) != std::string::npos)
        {
            results.push_back(entry);
            if (results.size() >= 5000) break;
        }
    }
    return results;
}

} // namespace openreverse
