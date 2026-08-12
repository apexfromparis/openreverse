#include "xref_scanner.h"
#include "utils/helpers.h"
#include <algorithm>
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
        uint64_t targetAddr = 0;
        XRefType type = XRefType::Read;

        if (ins.isCall && ins.targetAddress != 0)
        {
            targetAddr = ins.targetAddress;
            type = XRefType::Call;
        }
        else if (ins.isJump && ins.targetAddress != 0)
        {
            targetAddr = ins.targetAddress;
            type = XRefType::Jump;
        }
        else if (ins.mnemonic == "lea" && ins.targetKind == InstructionTargetKind::Memory)
        {
            targetAddr = ins.targetAddress;
            type = XRefType::Lea;
        }
        else if (ins.targetKind == InstructionTargetKind::Memory && ins.targetAddress != 0)
        {
            targetAddr = ins.targetAddress;
            type = ins.memoryRead && ins.memoryWrite ? XRefType::ReadWrite :
                (ins.memoryWrite ? XRefType::Write : XRefType::Read);
        }

        if (targetAddr != 0)
        {
            if (entries_.size() >= kMaxIndexedXRefs)
                break;
            size_t idx = entries_.size();
            XRefEntry entry;
            entry.fromAddress = ins.address;
            entry.toAddress = targetAddr;
            entry.type = type;
            entry.instructionText = ins.mnemonic + " " + ins.operands;
            entry.moduleName = moduleName;

            entries_.push_back(entry);
            toIndex_[targetAddr].push_back(idx);
            fromIndex_[ins.address].push_back(idx);
        }
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
