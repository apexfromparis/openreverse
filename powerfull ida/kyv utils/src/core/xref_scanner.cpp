// ============================================================================
// KYV - Core: Cross-References (XREFs) Scanner Implementation
// ============================================================================

#include "xref_scanner.h"
#include "utils/helpers.h"
#include "utils/logger.h"
#include <algorithm>
#include <sstream>

namespace kyv {

void XRefScanner::Clear()
{
    entries_.clear();
    toIndex_.clear();
    fromIndex_.clear();
}

void XRefScanner::ScanBuffer(const uint8_t* data, size_t dataSize, uint64_t baseAddress,
                             const std::string& moduleName, Disassembler& disasm, bool is64Bit)
{
    if (!data || dataSize == 0) return;

    auto insts = disasm.Disassemble(data, dataSize, baseAddress, (size_t)-1);

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
        else if (ins.mnemonic == "lea" && ins.targetAddress != 0)
        {
            targetAddr = ins.targetAddress;
            type = XRefType::Read; // LEA loads address of data/string
        }
        else if (ins.targetAddress != 0)
        {
            targetAddr = ins.targetAddress;
            if (ins.mnemonic == "mov" || ins.mnemonic == "push")
                type = XRefType::Read;
            else
                type = XRefType::Write;
        }

        if (targetAddr != 0)
        {
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

    Logger::Get().Log(LogLevel::Info, "XRefScanner indexed %zu references in %s",
                      entries_.size(), moduleName.empty() ? "module" : moduleName.c_str());
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

} // namespace kyv
