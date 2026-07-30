#pragma once
// ============================================================================
// KYV - Core: Cross-References (XREFs) Scanner & Indexer
// IDA Pro style code/data XREFs discovery and navigation engine
// ============================================================================

#include <string>
#include <vector>
#include <cstdint>
#include <map>
#include <windows.h>
#include "core/disassembler.h"

namespace kyv {

enum class XRefType {
    Call,
    Jump,
    Read,
    Write,
    Lea
};

struct XRefEntry {
    uint64_t    fromAddress = 0;
    uint64_t    toAddress = 0;
    XRefType    type = XRefType::Read;
    std::string instructionText;
    std::string moduleName;
};

class XRefScanner {
public:
    XRefScanner() = default;
    ~XRefScanner() = default;

    // Scan a buffer (.text section) and build the entire XREF index
    void ScanBuffer(const uint8_t* data, size_t dataSize, uint64_t baseAddress,
                    const std::string& moduleName, Disassembler& disasm, bool is64Bit);

    // Clear all indexed XREFs
    void Clear();

    // Query XREFs targeting a specific address (Who calls/references this?)
    std::vector<XRefEntry> FindXRefsTo(uint64_t targetAddress) const;

    // Query XREFs originating from a specific address (Where does this instruction jump/call/reference?)
    std::vector<XRefEntry> FindXRefsFrom(uint64_t sourceAddress) const;

    // Substring/fuzzy search across instruction operands and addresses
    std::vector<XRefEntry> SearchXRefsByText(const std::string& query) const;

    // Total indexed references
    size_t GetTotalXRefsCount() const { return entries_.size(); }

    const std::vector<XRefEntry>& GetAllEntries() const { return entries_; }

private:
    std::vector<XRefEntry> entries_;
    std::map<uint64_t, std::vector<size_t>> toIndex_;
    std::map<uint64_t, std::vector<size_t>> fromIndex_;
};

} // namespace kyv
