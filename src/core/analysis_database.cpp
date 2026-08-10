#include "analysis_database.h"

#include <algorithm>

namespace openreverse {

namespace {

void MergeFunctions(std::vector<FunctionInfo>& destination, const std::vector<FunctionInfo>& incoming)
{
    for (const auto& function : incoming)
    {
        auto existing = std::find_if(destination.begin(), destination.end(), [&](const FunctionInfo& value) {
            return value.startAddress == function.startAddress;
        });
        if (existing == destination.end())
            destination.push_back(function);
        else
            *existing = function;
    }
    std::sort(destination.begin(), destination.end(), [](const FunctionInfo& left, const FunctionInfo& right) {
        return left.startAddress < right.startAddress;
    });
}

void MergeXRefs(std::vector<XRefEntry>& destination, const std::vector<XRefEntry>& incoming)
{
    for (const auto& xref : incoming)
    {
        auto existing = std::find_if(destination.begin(), destination.end(), [&](const XRefEntry& value) {
            return value.fromAddress == xref.fromAddress && value.toAddress == xref.toAddress &&
                   value.type == xref.type;
        });
        if (existing == destination.end())
            destination.push_back(xref);
        else
            *existing = xref;
    }
}

void MergeStrings(std::vector<StringResult>& destination, const std::vector<StringResult>& incoming)
{
    for (const auto& string : incoming)
    {
        auto existing = std::find_if(destination.begin(), destination.end(), [&](const StringResult& value) {
            return value.address == string.address && value.encoding == string.encoding;
        });
        if (existing == destination.end())
            destination.push_back(string);
        else
            *existing = string;
    }
    std::sort(destination.begin(), destination.end(), [](const StringResult& left, const StringResult& right) {
        return left.address < right.address;
    });
}

} // namespace

void AnalysisDatabase::Clear()
{
    modules_.clear();
}

void AnalysisDatabase::RemoveModule(uint64_t moduleBase)
{
    modules_.erase(moduleBase);
}

uint64_t AnalysisDatabase::ReplaceModuleAnalysis(const ModuleInfo& module, bool is64Bit, const PEInfo& pe,
                                                  const std::vector<FunctionInfo>& functions,
                                                  const std::vector<XRefEntry>& xrefs,
                                                  const std::vector<StringResult>& strings,
                                                  const std::vector<GlobalCandidate>& globals,
                                                  const std::vector<FieldAccessCandidate>& fieldAccesses,
                                                  const std::vector<StructureCandidate>& structures)
{
    ModuleAnalysisState state;
    state.module = module;
    state.is64Bit = is64Bit;
    state.pe = pe;
    state.functions = functions;
    state.xrefs = xrefs;
    state.strings = strings;
    state.globals = globals;
    state.fieldAccesses = fieldAccesses;
    state.structures = structures;
    state.revision = nextRevision_++;
    modules_[module.baseAddress] = std::move(state);
    return modules_[module.baseAddress].revision;
}

uint64_t AnalysisDatabase::MergeModuleAnalysis(const ModuleInfo& module, bool is64Bit, const PEInfo& pe,
                                                const std::vector<FunctionInfo>& functions,
                                                const std::vector<XRefEntry>& xrefs,
                                                const std::vector<StringResult>& strings,
                                                const std::vector<GlobalCandidate>& globals,
                                                const std::vector<FieldAccessCandidate>& fieldAccesses,
                                                const std::vector<StructureCandidate>& structures)
{
    auto& state = modules_[module.baseAddress];
    state.module = module;
    state.is64Bit = is64Bit;
    if (pe.valid) state.pe = pe;
    MergeFunctions(state.functions, functions);
    MergeXRefs(state.xrefs, xrefs);
    MergeStrings(state.strings, strings);
    for (const auto& global : globals)
    {
        auto existing = std::find_if(state.globals.begin(), state.globals.end(), [&](const GlobalCandidate& value) {
            return value.address == global.address;
        });
        if (existing == state.globals.end()) state.globals.push_back(global); else *existing = global;
    }
    for (const auto& field : fieldAccesses)
    {
        auto existing = std::find_if(state.fieldAccesses.begin(), state.fieldAccesses.end(),
            [&](const FieldAccessCandidate& value) {
                return value.instructionAddress == field.instructionAddress && value.offset == field.offset &&
                       value.access == field.access && value.baseRegister == field.baseRegister;
            });
        if (existing == state.fieldAccesses.end()) state.fieldAccesses.push_back(field); else *existing = field;
    }
    for (const auto& structure : structures)
    {
        auto existing = std::find_if(state.structures.begin(), state.structures.end(),
            [&](const StructureCandidate& value) {
                return value.functionAddress == structure.functionAddress &&
                       value.baseRegister == structure.baseRegister;
            });
        if (existing == state.structures.end()) state.structures.push_back(structure); else *existing = structure;
    }
    state.revision = nextRevision_++;
    return state.revision;
}

const ModuleAnalysisState* AnalysisDatabase::GetModule(uint64_t moduleBase) const
{
    const auto module = modules_.find(moduleBase);
    return module == modules_.end() ? nullptr : &module->second;
}

const ModuleAnalysisState* AnalysisDatabase::FindModuleContaining(uint64_t address) const
{
    auto module = modules_.upper_bound(address);
    if (module == modules_.begin()) return nullptr;
    --module;
    const auto& info = module->second.module;
    return address >= info.baseAddress && address - info.baseAddress < info.size ? &module->second : nullptr;
}

} // namespace openreverse
