#pragma once

#include "core/function_analyzer.h"
#include "core/data_analyzer.h"
#include "core/module_manager.h"
#include "core/pe_parser.h"
#include "core/string_scanner.h"
#include "core/xref_scanner.h"

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
                                   const std::vector<StructureCandidate>& structures = {});
    uint64_t MergeModuleAnalysis(const ModuleInfo& module, bool is64Bit, const PEInfo& pe,
                                 const std::vector<FunctionInfo>& functions,
                                 const std::vector<XRefEntry>& xrefs,
                                 const std::vector<StringResult>& strings,
                                 const std::vector<GlobalCandidate>& globals = {},
                                 const std::vector<FieldAccessCandidate>& fieldAccesses = {},
                                 const std::vector<StructureCandidate>& structures = {});

    const ModuleAnalysisState* GetModule(uint64_t moduleBase) const;
    const ModuleAnalysisState* FindModuleContaining(uint64_t address) const;
    const std::map<uint64_t, ModuleAnalysisState>& GetModules() const { return modules_; }

private:
    uint64_t nextRevision_ = 1;
    std::map<uint64_t, ModuleAnalysisState> modules_;
};

} // namespace openreverse
