#pragma once

#include "core/function_analyzer.h"
#include "core/data_analyzer.h"
#include "core/module_manager.h"
#include "core/pe_parser.h"
#include "core/string_scanner.h"
#include "core/xref_scanner.h"
#include "core/offset_model.h"
#include "core/symbol_provider.h"

#include <cstdint>
#include <map>
#include <vector>

namespace openreverse {

struct ModuleAnalysisState {
    ModuleInfo module{};
    bool is64Bit = false;
    PEInfo pe{};
    std::vector<FunctionInfo> functions;
    std::vector<XRefEntry> xrefs;
    std::vector<StringResult> strings;
    std::vector<GlobalCandidate> globals;
    std::vector<FieldAccessCandidate> fieldAccesses;
    std::vector<StructureCandidate> structures;
    std::vector<OffsetRecord> offsets;
    std::vector<SignatureRecord> signatures;
    ModuleIdentity identity;
    std::vector<SymbolRecord> symbols;
    std::vector<SymbolTypeRecord> symbolTypes;
    SymbolProviderIdentity symbolIdentity;
    std::map<uint64_t, size_t> functionByAddress;
    std::multimap<uint64_t, size_t> xrefsBySource;
    std::multimap<uint64_t, size_t> xrefsByTarget;
    std::map<uint64_t, size_t> stringsByAddress;
    std::map<uint64_t, size_t> globalsByAddress;
    uint64_t revision = 0;
};

class AnalysisDatabase {
public:
    void Clear();
    void RemoveModule(uint64_t moduleBase);

    uint64_t ReplaceModuleAnalysis(const ModuleInfo& module, bool is64Bit, const PEInfo& pe,
                                   const std::vector<FunctionInfo>& functions,
                                   const std::vector<XRefEntry>& xrefs,
                                   const std::vector<StringResult>& strings,
                                   const std::vector<GlobalCandidate>& globals = {},
                                   const std::vector<FieldAccessCandidate>& fieldAccesses = {},
                                   const std::vector<StructureCandidate>& structures = {},
                                   const std::vector<OffsetRecord>& offsets = {},
                                   const std::vector<SignatureRecord>& signatures = {},
                                   const ModuleIdentity& identity = {},
                                   const std::vector<SymbolRecord>& symbols = {},
                                   const std::vector<SymbolTypeRecord>& symbolTypes = {},
                                   const SymbolProviderIdentity& symbolIdentity = {});
    uint64_t MergeModuleAnalysis(const ModuleInfo& module, bool is64Bit, const PEInfo& pe,
                                 const std::vector<FunctionInfo>& functions,
                                 const std::vector<XRefEntry>& xrefs,
                                 const std::vector<StringResult>& strings,
                                 const std::vector<GlobalCandidate>& globals = {},
                                 const std::vector<FieldAccessCandidate>& fieldAccesses = {},
                                 const std::vector<StructureCandidate>& structures = {},
                                 const std::vector<OffsetRecord>& offsets = {},
                                 const std::vector<SignatureRecord>& signatures = {},
                                 const ModuleIdentity& identity = {},
                                 const std::vector<SymbolRecord>& symbols = {},
                                 const std::vector<SymbolTypeRecord>& symbolTypes = {},
                                 const SymbolProviderIdentity& symbolIdentity = {});

    const ModuleAnalysisState* GetModule(uint64_t moduleBase) const;
    const ModuleAnalysisState* FindModuleContaining(uint64_t address) const;
    const FunctionInfo* FindFunction(uint64_t moduleBase, uint64_t address) const;
    const FunctionInfo* FindFunctionContaining(uint64_t moduleBase, uint64_t address) const;
    std::vector<const XRefEntry*> FindXRefsTo(uint64_t moduleBase, uint64_t address) const;
    std::vector<const XRefEntry*> FindXRefsFrom(uint64_t moduleBase, uint64_t address) const;
    const GlobalCandidate* FindGlobal(uint64_t moduleBase, uint64_t address) const;
    bool UpsertOffset(uint64_t moduleBase, const OffsetRecord& offset);
    const std::map<uint64_t, ModuleAnalysisState>& GetModules() const { return modules_; }

private:
    uint64_t nextRevision_ = 1;
    std::map<uint64_t, ModuleAnalysisState> modules_;
};

} // namespace openreverse
