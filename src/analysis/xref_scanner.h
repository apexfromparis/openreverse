#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <map>
#include <windows.h>
#include "analysis/disassembler.h"

namespace openreverse {

enum class XRefType {
    Call,
    Jump,
    Read,
    Write,
    ReadWrite,
    Address,
    String,
    Import,
    Global,
    Data
};

struct XRefEntry {
    uint64_t    fromAddress = 0;
    uint64_t    toAddress = 0;
    XRefType    type = XRefType::Read;
    uint8_t     operandIndex = 0;
    uint8_t     operandSize = 0;
    uint64_t    functionAddress = 0;
    std::string instructionText;
    std::string moduleName;
};

struct FunctionInfo;
void AssignXRefFunctions(std::vector<XRefEntry>& xrefs,
                         const std::vector<FunctionInfo>& functions);

class XRefScanner {
public:
    XRefScanner() = default;
    ~XRefScanner() = default;

    void ScanBuffer(const uint8_t* data, size_t dataSize, uint64_t baseAddress,
                    const std::string& moduleName, Disassembler& disasm, bool is64Bit);
    void ScanInstructions(const std::vector<Instruction>& instructions, const std::string& moduleName);

    void Clear();

    // Replace the index from an immutable analysis result on the owning thread.
    void ReplaceEntries(std::vector<XRefEntry> entries);

    std::vector<XRefEntry> FindXRefsTo(uint64_t targetAddress) const;

    std::vector<XRefEntry> FindXRefsFrom(uint64_t sourceAddress) const;

    std::vector<XRefEntry> SearchXRefsByText(const std::string& query) const;

    size_t GetTotalXRefsCount() const { return entries_.size(); }

    const std::vector<XRefEntry>& GetAllEntries() const { return entries_; }

private:
    std::vector<XRefEntry> entries_;
    std::map<uint64_t, std::vector<size_t>> toIndex_;
    std::map<uint64_t, std::vector<size_t>> fromIndex_;
};

} // namespace openreverse
