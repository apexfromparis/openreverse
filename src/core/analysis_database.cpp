#include "analysis_database.h"

#include <algorithm>
#include <tuple>

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
                   value.type == xref.type && value.operandIndex == xref.operandIndex;
        });
        if (existing == destination.end())
            destination.push_back(xref);
        else
            *existing = xref;
    }
    std::sort(destination.begin(), destination.end(), [](const XRefEntry& left, const XRefEntry& right) {
        return std::tie(left.fromAddress, left.operandIndex, left.toAddress, left.type) <
            std::tie(right.fromAddress, right.operandIndex, right.toAddress, right.type);
    });
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

void RebuildIndexes(ModuleAnalysisState& state)
{
    state.functionByAddress.clear();
    state.xrefsBySource.clear();
    state.xrefsByTarget.clear();
    state.stringsByAddress.clear();
    state.globalsByAddress.clear();
    for (size_t index = 0; index < state.functions.size(); ++index)
        state.functionByAddress[state.functions[index].startAddress] = index;
    for (size_t index = 0; index < state.xrefs.size(); ++index)
    {
        state.xrefsBySource.emplace(state.xrefs[index].fromAddress, index);
        state.xrefsByTarget.emplace(state.xrefs[index].toAddress, index);
    }
    for (size_t index = 0; index < state.strings.size(); ++index)
        state.stringsByAddress[state.strings[index].address] = index;
    for (size_t index = 0; index < state.globals.size(); ++index)
        state.globalsByAddress[state.globals[index].address] = index;
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
                                                  const std::vector<StructureCandidate>& structures,
                                                  const std::vector<OffsetRecord>& offsets,
                                                  const std::vector<SignatureRecord>& signatures,
                                                  const ModuleIdentity& identity,
                                                  const std::vector<SymbolRecord>& symbols,
                                                  const std::vector<SymbolTypeRecord>& symbolTypes,
                                                  const SymbolProviderIdentity& symbolIdentity)
{
    std::vector<OffsetRecord> preservedUserOffsets;
    const auto previous = modules_.find(module.baseAddress);
    if (previous != modules_.end())
    {
        for (const auto& offset : previous->second.offsets)
            if (offset.kind == OffsetKind::UserDefined)
                preservedUserOffsets.push_back(offset);
    }
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
    state.offsets = offsets;
    for (const auto& offset : preservedUserOffsets)
    {
        const auto existing = std::find_if(state.offsets.begin(), state.offsets.end(),
            [&](const OffsetRecord& value) { return value.stableId == offset.stableId; });
        if (existing == state.offsets.end()) state.offsets.push_back(offset);
    }
    state.signatures = signatures;
    state.identity = identity;
    state.symbols = symbols;
    state.symbolTypes = symbolTypes;
    state.symbolIdentity = symbolIdentity;
    RebuildIndexes(state);
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
                                                const std::vector<StructureCandidate>& structures,
                                                const std::vector<OffsetRecord>& offsets,
                                                const std::vector<SignatureRecord>& signatures,
                                                const ModuleIdentity& identity,
                                                const std::vector<SymbolRecord>& symbols,
                                                const std::vector<SymbolTypeRecord>& symbolTypes,
                                                const SymbolProviderIdentity& symbolIdentity)
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
    for (const auto& offset : offsets)
    {
        auto existing = std::find_if(state.offsets.begin(), state.offsets.end(), [&](const OffsetRecord& value) {
            return !offset.stableId.empty() ? value.stableId == offset.stableId :
                value.kind == offset.kind && value.rva == offset.rva && value.fieldOffset == offset.fieldOffset;
        });
        if (existing == state.offsets.end()) state.offsets.push_back(offset); else *existing = offset;
    }
    for (const auto& signature : signatures)
    {
        auto existing = std::find_if(state.signatures.begin(), state.signatures.end(),
            [&](const SignatureRecord& value) { return value.stableId == signature.stableId; });
        if (existing == state.signatures.end()) state.signatures.push_back(signature); else *existing = signature;
    }
    if (!identity.sha256.empty()) state.identity = identity;
    if (!symbols.empty()) state.symbols = symbols;
    if (!symbolTypes.empty()) state.symbolTypes = symbolTypes;
    if (!symbolIdentity.guid.empty()) state.symbolIdentity = symbolIdentity;
    state.revision = nextRevision_++;
    RebuildIndexes(state);
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

const FunctionInfo* AnalysisDatabase::FindFunction(uint64_t moduleBase, uint64_t address) const
{
    const auto* module = GetModule(moduleBase);
    if (!module) return nullptr;
    const auto found = module->functionByAddress.find(address);
    return found == module->functionByAddress.end() ? nullptr : &module->functions[found->second];
}

const FunctionInfo* AnalysisDatabase::FindFunctionContaining(uint64_t moduleBase, uint64_t address) const
{
    const auto* module = GetModule(moduleBase);
    if (!module || module->functionByAddress.empty()) return nullptr;
    auto found = module->functionByAddress.upper_bound(address);
    if (found == module->functionByAddress.begin()) return nullptr;
    --found;
    const auto& function = module->functions[found->second];
    const uint64_t end = function.boundaryKnown ? function.endAddress : function.analysisLimit;
    return end > function.startAddress && address < end ? &function : nullptr;
}

std::vector<const XRefEntry*> AnalysisDatabase::FindXRefsTo(uint64_t moduleBase, uint64_t address) const
{
    std::vector<const XRefEntry*> result;
    const auto* module = GetModule(moduleBase);
    if (!module) return result;
    const auto range = module->xrefsByTarget.equal_range(address);
    for (auto entry = range.first; entry != range.second; ++entry)
        result.push_back(&module->xrefs[entry->second]);
    return result;
}

std::vector<const XRefEntry*> AnalysisDatabase::FindXRefsFrom(uint64_t moduleBase, uint64_t address) const
{
    std::vector<const XRefEntry*> result;
    const auto* module = GetModule(moduleBase);
    if (!module) return result;
    const auto range = module->xrefsBySource.equal_range(address);
    for (auto entry = range.first; entry != range.second; ++entry)
        result.push_back(&module->xrefs[entry->second]);
    return result;
}

const GlobalCandidate* AnalysisDatabase::FindGlobal(uint64_t moduleBase, uint64_t address) const
{
    const auto* module = GetModule(moduleBase);
    if (!module) return nullptr;
    const auto found = module->globalsByAddress.find(address);
    return found == module->globalsByAddress.end() ? nullptr : &module->globals[found->second];
}

bool AnalysisDatabase::UpsertOffset(uint64_t moduleBase, const OffsetRecord& offset)
{
    auto module = modules_.find(moduleBase);
    if (module == modules_.end()) return false;
    auto& offsets = module->second.offsets;
    const auto existing = std::find_if(offsets.begin(), offsets.end(), [&](const OffsetRecord& value) {
        return !offset.stableId.empty() && value.stableId == offset.stableId;
    });
    if (existing == offsets.end()) offsets.push_back(offset); else *existing = offset;
    std::sort(offsets.begin(), offsets.end(), [](const OffsetRecord& left, const OffsetRecord& right) {
        return std::tie(left.kind, left.rva, left.fieldOffset, left.stableId) <
            std::tie(right.kind, right.rva, right.fieldOffset, right.stableId);
    });
    module->second.revision = nextRevision_++;
    return true;
}

} // namespace openreverse
