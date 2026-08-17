#include "version_intelligence.h"

#include "core/disassembler.h"
#include "core/pattern_scanner.h"
#include "core/signature_engine.h"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

namespace openreverse {

namespace {

uint32_t BoundedCount(size_t value)
{
    return static_cast<uint32_t>(std::min<size_t>(value, (std::numeric_limits<uint32_t>::max)()));
}

std::string Hex(uint64_t value)
{
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << value;
    return stream.str();
}

template<typename T>
std::vector<T> AddedValues(const std::vector<T>& oldValues, const std::vector<T>& newValues)
{
    std::set<T> oldSet(oldValues.begin(), oldValues.end());
    std::set<T> newSet(newValues.begin(), newValues.end());
    std::vector<T> result;
    std::set_difference(newSet.begin(), newSet.end(), oldSet.begin(), oldSet.end(),
                        std::back_inserter(result));
    return result;
}

uint64_t InstructionRole(const Instruction& instruction)
{
    uint64_t role = instruction.instructionId;
    for (const auto& operand : instruction.decodedOperands)
    {
        role = role * 1315423911ULL + static_cast<uint64_t>(operand.type) * 17ULL + operand.size;
        role = role * 33ULL + (operand.read ? 1ULL : 0ULL) + (operand.write ? 2ULL : 0ULL);
        if (operand.type == OperandType::Memory)
        {
            role = role * 33ULL + (operand.memory.ripRelative ? 1ULL : 0ULL);
            role = role * 33ULL + operand.memory.scale;
        }
    }
    return role;
}

uint64_t InstructionRole(const FunctionInfo& function, uint64_t address)
{
    for (const auto& block : function.cfg.basicBlocks)
        for (const auto& instruction : block.instructions)
            if (instruction.address == address) return InstructionRole(instruction);
    return 0;
}

const FunctionInfo* FindFunctionByAddress(const ModuleAnalysisState& analysis, uint64_t address)
{
    const auto found = std::find_if(analysis.functions.begin(), analysis.functions.end(),
        [&](const FunctionInfo& function) { return function.startAddress == address; });
    return found == analysis.functions.end() ? nullptr : &*found;
}

const FunctionInfo* FindFunctionByRva(const ModuleAnalysisState& analysis, uint64_t rva)
{
    return FindFunctionByAddress(analysis, analysis.module.baseAddress + rva);
}

std::string GlobalRole(const GlobalCandidate& global)
{
    std::ostringstream stream;
    stream << global.sectionName << ':' << static_cast<unsigned>(global.kind) << ':'
           << (global.readCount != 0 ? 'R' : '-') << (global.writeCount != 0 ? 'W' : '-')
           << (global.addressCount != 0 ? 'A' : '-');
    return stream.str();
}

std::vector<FunctionFingerprintContext> BuildContexts(const ModuleAnalysisState& analysis)
{
    std::vector<FunctionFingerprintContext> contexts(analysis.functions.size());
    std::unordered_map<uint64_t, size_t> functionIndexes;
    std::unordered_map<uint64_t, const StringResult*> stringsByAddress;
    std::unordered_map<uint64_t, const GlobalCandidate*> globalsByAddress;
    std::vector<std::unordered_map<uint64_t, uint64_t>> instructionRoles(analysis.functions.size());
    for (size_t index = 0; index < analysis.functions.size(); ++index)
    {
        const auto& function = analysis.functions[index];
        functionIndexes[function.startAddress] = index;
        contexts[index].imageBase = analysis.module.baseAddress;
        contexts[index].imageSize = analysis.module.size;
        for (const auto& block : function.cfg.basicBlocks)
            for (const auto& instruction : block.instructions)
                instructionRoles[index][instruction.address] = InstructionRole(instruction);
    }
    for (const auto& value : analysis.strings) stringsByAddress[value.address] = &value;
    for (const auto& value : analysis.globals) globalsByAddress[value.address] = &value;

    for (const auto& xref : analysis.xrefs)
    {
        const auto function = functionIndexes.find(xref.functionAddress);
        if (function == functionIndexes.end()) continue;
        auto& context = contexts[function->second];
        if (xref.type == XRefType::String)
        {
            const auto value = stringsByAddress.find(xref.toAddress);
            if (value != stringsByAddress.end())
                context.referencedStrings.push_back(value->second->value);
        }
        else if (xref.type == XRefType::Import)
            context.referencedImports.push_back(xref.instructionText);
        else if (xref.type == XRefType::Global || xref.type == XRefType::Read ||
                 xref.type == XRefType::Write || xref.type == XRefType::ReadWrite)
        {
            const auto global = globalsByAddress.find(xref.toAddress);
            if (global != globalsByAddress.end())
                context.referencedGlobals.push_back(GlobalRole(*global->second));
        }
    }
    for (const auto& signature : analysis.signatures)
    {
        const auto function = functionIndexes.find(signature.targetFunction);
        if (function != functionIndexes.end())
            contexts[function->second].signatureFragments.push_back(
                SignatureEngine::FormatPattern(signature.pattern));
    }
    for (const auto& symbol : analysis.symbols)
    {
        if (symbol.kind != SymbolKind::Function || symbol.name.empty()) continue;
        const auto function = functionIndexes.find(analysis.module.baseAddress + symbol.rva);
        if (function != functionIndexes.end())
            contexts[function->second].symbolNames.push_back(symbol.name);
    }
    for (const auto& field : analysis.fieldAccesses)
    {
        const auto function = functionIndexes.find(field.functionAddress);
        if (function == functionIndexes.end()) continue;
        const auto role = instructionRoles[function->second].find(field.instructionAddress);
        contexts[function->second].fields.push_back({field.argumentIndex, field.displacement,
            field.operandSize, static_cast<uint8_t>(field.access),
            role == instructionRoles[function->second].end() ? 0 : role->second});
    }
    for (auto& context : contexts)
    {
        std::sort(context.referencedStrings.begin(), context.referencedStrings.end());
        std::sort(context.referencedImports.begin(), context.referencedImports.end());
        std::sort(context.referencedGlobals.begin(), context.referencedGlobals.end());
        std::sort(context.signatureFragments.begin(), context.signatureFragments.end());
        std::sort(context.symbolNames.begin(), context.symbolNames.end());
    }
    return contexts;
}

std::vector<FunctionFingerprint> BuildFingerprints(const ModuleAnalysisState& analysis)
{
    const auto contexts = BuildContexts(analysis);
    std::vector<FunctionFingerprint> fingerprints;
    fingerprints.reserve(analysis.functions.size());
    for (size_t index = 0; index < analysis.functions.size(); ++index)
        fingerprints.push_back(BuildFunctionFingerprint(analysis.functions[index], contexts[index]));
    return fingerprints;
}

VersionEvidence SimilarityEvidence(VersionEvidenceKind kind, double score, size_t oldCount,
                                   size_t newCount, const std::string& detail)
{
    return {kind, score, BoundedCount(oldCount), BoundedCount(newCount), detail};
}

std::vector<VersionEvidence> BuildEvidence(const FunctionFingerprint& oldFingerprint,
                                           const FunctionFingerprint& newFingerprint,
                                           const FunctionSimilarityBreakdown& similarity)
{
    std::vector<VersionEvidence> evidence;
    evidence.push_back(SimilarityEvidence(VersionEvidenceKind::NormalizedCode,
        similarity.normalizedInstructions, oldFingerprint.instructionCount,
        newFingerprint.instructionCount, similarity.exactNormalized
            ? "normalized instruction sequence is identical"
            : "normalized instruction multiset comparison"));
    evidence.push_back(SimilarityEvidence(VersionEvidenceKind::OrderedCode,
        similarity.orderedInstructions, oldFingerprint.orderedInstructionNgrams.size(),
        newFingerprint.orderedInstructionNgrams.size(),
        "ordered normalized instruction windows"));
    evidence.push_back(SimilarityEvidence(VersionEvidenceKind::Cfg, similarity.cfg,
        oldFingerprint.basicBlockCount, newFingerprint.basicBlockCount,
        oldFingerprint.cfgHash == newFingerprint.cfgHash
            ? "block-content CFG neighborhoods match"
            : "block-content CFG neighborhoods differ"));
    evidence.push_back(SimilarityEvidence(VersionEvidenceKind::Calls, similarity.calls,
        oldFingerprint.callCount, newFingerprint.callCount, "decoded direct-call count"));
    if (!oldFingerprint.referencedStrings.empty() || !newFingerprint.referencedStrings.empty())
        evidence.push_back(SimilarityEvidence(VersionEvidenceKind::Strings, similarity.strings,
            oldFingerprint.referencedStrings.size(), newFingerprint.referencedStrings.size(),
            "referenced string multiset"));
    if (!oldFingerprint.referencedImports.empty() || !newFingerprint.referencedImports.empty())
        evidence.push_back(SimilarityEvidence(VersionEvidenceKind::Imports, similarity.imports,
            oldFingerprint.referencedImports.size(), newFingerprint.referencedImports.size(),
            "import-reference roles"));
    if (!oldFingerprint.referencedGlobals.empty() || !newFingerprint.referencedGlobals.empty())
        evidence.push_back(SimilarityEvidence(VersionEvidenceKind::Globals, similarity.globals,
            oldFingerprint.referencedGlobals.size(), newFingerprint.referencedGlobals.size(),
            "global access roles"));
    if (!oldFingerprint.signatureFragments.empty() || !newFingerprint.signatureFragments.empty())
        evidence.push_back(SimilarityEvidence(VersionEvidenceKind::Signature, similarity.signatures,
            oldFingerprint.signatureFragments.size(), newFingerprint.signatureFragments.size(),
            "stable signature fragments"));
    if (!oldFingerprint.symbolNames.empty() || !newFingerprint.symbolNames.empty())
        evidence.push_back(SimilarityEvidence(VersionEvidenceKind::Symbol, similarity.symbols,
            oldFingerprint.symbolNames.size(), newFingerprint.symbolNames.size(),
            "validated PDB function names"));
    if (oldFingerprint.boundaryKnown && newFingerprint.boundaryKnown)
        evidence.push_back(SimilarityEvidence(VersionEvidenceKind::RuntimeBoundary,
            oldFingerprint.authoritativeSize == newFingerprint.authoritativeSize ? 1.0 : similarity.size,
            oldFingerprint.authoritativeSize, newFingerprint.authoritativeSize,
            "authoritative runtime-function boundaries"));
    return evidence;
}

std::string FieldLabel(const FunctionFieldFingerprint& field)
{
    const uint64_t magnitude = field.displacement < 0
        ? static_cast<uint64_t>(-(field.displacement + 1)) + 1
        : static_cast<uint64_t>(field.displacement);
    std::ostringstream stream;
    stream << "Arg" << static_cast<unsigned>(field.argumentIndex) << (field.displacement < 0 ? "-0x" : "+0x")
           << std::hex << std::uppercase << magnitude
           << "/" << std::dec << static_cast<unsigned>(field.width) << "B";
    return stream.str();
}

FunctionChangeSummary BuildChanges(const FunctionFingerprint& oldFingerprint,
                                   const FunctionFingerprint& newFingerprint)
{
    FunctionChangeSummary changes;
    changes.instructionDelta = static_cast<int64_t>(newFingerprint.instructionCount) -
        static_cast<int64_t>(oldFingerprint.instructionCount);
    changes.basicBlockDelta = static_cast<int64_t>(newFingerprint.basicBlockCount) -
        static_cast<int64_t>(oldFingerprint.basicBlockCount);
    changes.edgeDelta = static_cast<int64_t>(newFingerprint.edgeCount) -
        static_cast<int64_t>(oldFingerprint.edgeCount);
    changes.callDelta = static_cast<int64_t>(newFingerprint.callCount) -
        static_cast<int64_t>(oldFingerprint.callCount);
    changes.addedStrings = AddedValues(oldFingerprint.referencedStrings, newFingerprint.referencedStrings);
    changes.removedStrings = AddedValues(newFingerprint.referencedStrings, oldFingerprint.referencedStrings);
    changes.addedImports = AddedValues(oldFingerprint.referencedImports, newFingerprint.referencedImports);
    changes.removedImports = AddedValues(newFingerprint.referencedImports, oldFingerprint.referencedImports);
    changes.addedGlobals = AddedValues(oldFingerprint.referencedGlobals, newFingerprint.referencedGlobals);
    changes.removedGlobals = AddedValues(newFingerprint.referencedGlobals, oldFingerprint.referencedGlobals);
    std::vector<std::string> oldFields;
    std::vector<std::string> newFields;
    for (const auto& field : oldFingerprint.fields) oldFields.push_back(FieldLabel(field));
    for (const auto& field : newFingerprint.fields) newFields.push_back(FieldLabel(field));
    changes.addedFields = AddedValues(oldFields, newFields);
    changes.removedFields = AddedValues(newFields, oldFields);
    return changes;
}

void AddIndexValues(std::unordered_map<std::string, std::vector<size_t>>& index,
                    const std::vector<std::string>& values, size_t functionIndex)
{
    std::set<std::string> unique(values.begin(), values.end());
    for (const auto& value : unique)
        if (!value.empty()) index[value].push_back(functionIndex);
}

void AddIndexValues(std::unordered_map<uint64_t, std::vector<size_t>>& index,
                    const std::vector<uint64_t>& values, size_t functionIndex)
{
    std::set<uint64_t> unique(values.begin(), values.end());
    for (uint64_t value : unique) index[value].push_back(functionIndex);
}

struct FingerprintIndexes {
    std::unordered_map<uint64_t, std::vector<size_t>> normalized;
    std::unordered_map<uint64_t, std::vector<size_t>> cfg;
    std::unordered_map<uint64_t, std::vector<size_t>> orderedInstructions;
    std::unordered_map<uint64_t, std::vector<size_t>> cfgNeighborhoods;
    std::unordered_map<size_t, std::vector<size_t>> instructionBuckets;
    std::unordered_map<std::string, std::vector<size_t>> strings;
    std::unordered_map<std::string, std::vector<size_t>> imports;
    std::unordered_map<std::string, std::vector<size_t>> globals;
    std::unordered_map<std::string, std::vector<size_t>> signatures;
    std::unordered_map<std::string, std::vector<size_t>> symbols;
};

FingerprintIndexes BuildIndexes(const std::vector<FunctionFingerprint>& fingerprints)
{
    FingerprintIndexes indexes;
    for (size_t index = 0; index < fingerprints.size(); ++index)
    {
        const auto& fingerprint = fingerprints[index];
        indexes.normalized[fingerprint.normalizedHash].push_back(index);
        indexes.cfg[fingerprint.cfgHash].push_back(index);
        AddIndexValues(indexes.orderedInstructions,
                       fingerprint.orderedInstructionNgrams, index);
        AddIndexValues(indexes.cfgNeighborhoods,
                       fingerprint.cfgNeighborhoodTokens, index);
        indexes.instructionBuckets[fingerprint.instructionCount / 4].push_back(index);
        AddIndexValues(indexes.strings, fingerprint.referencedStrings, index);
        AddIndexValues(indexes.imports, fingerprint.referencedImports, index);
        AddIndexValues(indexes.globals, fingerprint.referencedGlobals, index);
        AddIndexValues(indexes.signatures, fingerprint.signatureFragments, index);
        AddIndexValues(indexes.symbols, fingerprint.symbolNames, index);
    }
    return indexes;
}

template<typename K>
void IncludeIndexed(const std::unordered_map<K, std::vector<size_t>>& index, const K& key,
                    std::unordered_set<size_t>& candidates, size_t maximumBucket = 0)
{
    const auto found = index.find(key);
    if (found == index.end()) return;
    if (maximumBucket != 0 && found->second.size() > maximumBucket) return;
    candidates.insert(found->second.begin(), found->second.end());
}

std::vector<size_t> CandidateIndexes(const FunctionFingerprint& oldFingerprint,
                                     const FingerprintIndexes& newIndexes,
                                     bool& budgetReached)
{
    constexpr size_t kMaximumIndexedCandidatesPerFunction = 4096;
    std::unordered_set<size_t> candidates;
    IncludeIndexed(newIndexes.normalized, oldFingerprint.normalizedHash, candidates);
    IncludeIndexed(newIndexes.cfg, oldFingerprint.cfgHash, candidates);
    for (uint64_t value : oldFingerprint.orderedInstructionNgrams)
        IncludeIndexed(newIndexes.orderedInstructions, value, candidates, 256);
    for (uint64_t value : oldFingerprint.cfgNeighborhoodTokens)
        IncludeIndexed(newIndexes.cfgNeighborhoods, value, candidates, 256);
    for (const auto& value : oldFingerprint.referencedStrings)
        IncludeIndexed(newIndexes.strings, value, candidates, 1024);
    for (const auto& value : oldFingerprint.referencedImports)
        IncludeIndexed(newIndexes.imports, value, candidates, 1024);
    for (const auto& value : oldFingerprint.referencedGlobals)
        IncludeIndexed(newIndexes.globals, value, candidates, 1024);
    for (const auto& value : oldFingerprint.signatureFragments)
        IncludeIndexed(newIndexes.signatures, value, candidates, 1024);
    for (const auto& value : oldFingerprint.symbolNames)
        IncludeIndexed(newIndexes.symbols, value, candidates, 1024);
    if (candidates.empty())
    {
        const size_t bucket = oldFingerprint.instructionCount / 4;
        IncludeIndexed(newIndexes.instructionBuckets, bucket, candidates);
        if (bucket != 0) IncludeIndexed(newIndexes.instructionBuckets, bucket - 1, candidates);
        IncludeIndexed(newIndexes.instructionBuckets, bucket + 1, candidates);
    }
    std::vector<size_t> result(candidates.begin(), candidates.end());
    std::sort(result.begin(), result.end());
    if (result.size() > kMaximumIndexedCandidatesPerFunction)
    {
        result.resize(kMaximumIndexedCandidatesPerFunction);
        budgetReached = true;
    }
    return result;
}

bool HasStrongAnchor(const FunctionFingerprint& fingerprint)
{
    return fingerprint.instructionCount >= 4 || !fingerprint.referencedStrings.empty() ||
        !fingerprint.referencedImports.empty() || !fingerprint.referencedGlobals.empty() ||
        !fingerprint.signatureFragments.empty() || !fingerprint.symbolNames.empty();
}

VersionMatchState CandidateState(const FunctionFingerprint& oldFingerprint,
                                 const FunctionFingerprint& newFingerprint,
                                 const FunctionSimilarityBreakdown& similarity)
{
    const bool anchored = HasStrongAnchor(oldFingerprint) || HasStrongAnchor(newFingerprint);
    if (similarity.exactNormalized && anchored) return VersionMatchState::Exact;
    if (similarity.total >= 0.82 && anchored) return VersionMatchState::StrongCandidate;
    return VersionMatchState::Candidate;
}

std::map<uint64_t, uint64_t> ConfidentFunctionMap(const VersionComparison& comparison)
{
    std::map<uint64_t, uint64_t> result;
    for (const auto& match : comparison.functions)
    {
        const VersionMatchState state = EffectiveState(match.suggestedState, match.decision);
        if ((state == VersionMatchState::Exact || state == VersionMatchState::StrongCandidate ||
             state == VersionMatchState::Accepted) && !match.candidates.empty())
        {
            const uint64_t selected = state == VersionMatchState::Accepted && match.decisionNewRva != 0
                ? match.decisionNewRva : match.candidates.front().newRva;
            result[match.oldRva] = selected;
        }
    }
    return result;
}

void RefineWithMatchedCallees(VersionComparison& comparison,
                              const std::vector<FunctionFingerprint>& oldFingerprints,
                              const std::vector<FunctionFingerprint>& newFingerprints)
{
    const auto confident = ConfidentFunctionMap(comparison);
    if (confident.empty()) return;
    std::map<uint64_t, const FunctionFingerprint*> oldByRva;
    std::map<uint64_t, const FunctionFingerprint*> newByRva;
    for (const auto& fingerprint : oldFingerprints) oldByRva[fingerprint.functionRva] = &fingerprint;
    for (const auto& fingerprint : newFingerprints) newByRva[fingerprint.functionRva] = &fingerprint;
    for (auto& match : comparison.functions)
    {
        const auto oldFound = oldByRva.find(match.oldRva);
        if (oldFound == oldByRva.end()) continue;
        for (auto& candidate : match.candidates)
        {
            const auto newFound = newByRva.find(candidate.newRva);
            if (newFound == newByRva.end()) continue;
            size_t supported = 0;
            size_t comparable = 0;
            for (uint64_t oldCall : oldFound->second->callTargets)
            {
                if (oldCall < comparison.oldTarget.imageBase) continue;
                const uint64_t oldCalleeRva = oldCall - comparison.oldTarget.imageBase;
                const auto mapped = confident.find(oldCalleeRva);
                if (mapped == confident.end()) continue;
                ++comparable;
                const uint64_t expected = comparison.newTarget.imageBase + mapped->second;
                if (std::find(newFound->second->callTargets.begin(), newFound->second->callTargets.end(),
                              expected) != newFound->second->callTargets.end())
                    ++supported;
            }
            if (comparable == 0) continue;
            const double score = static_cast<double>(supported) / comparable;
            candidate.evidence.push_back(SimilarityEvidence(VersionEvidenceKind::MatchedCallees,
                score, comparable, supported, "only previously exact/strong callee mappings contribute"));
            if (candidate.similarityScore >= 0.72)
                candidate.similarityScore = std::min(1.0, candidate.similarityScore + score * 0.08);
        }
        std::sort(match.candidates.begin(), match.candidates.end(), [](const auto& left, const auto& right) {
            if (left.similarityScore != right.similarityScore) return left.similarityScore > right.similarityScore;
            return left.newRva < right.newRva;
        });
        if (match.suggestedState == VersionMatchState::Candidate && !match.candidates.empty() &&
            match.candidates.front().similarityScore >= 0.82 &&
            (match.candidates.size() == 1 || match.candidates[0].similarityScore -
             match.candidates[1].similarityScore > 0.05))
            match.suggestedState = VersionMatchState::StrongCandidate;
    }
}

VersionMigrationCandidate MigrateGlobal(const GlobalCandidate& oldGlobal,
                                        const VersionAnalysisTarget& oldTarget,
                                        const VersionAnalysisTarget& newTarget,
                                        const std::map<uint64_t, uint64_t>& functionMap)
{
    VersionMigrationCandidate migration;
    migration.stableId = "global:" + Hex(oldGlobal.rva);
    migration.kind = VersionMigrationKind::Global;
    migration.offsetKind = OffsetKind::GlobalRva;
    migration.oldRva = oldGlobal.rva;
    migration.oldSupportRva = oldGlobal.accessSites.empty() ? 0 :
        oldGlobal.accessSites.front() - oldTarget.analysis.module.baseAddress;
    struct Candidate { const GlobalCandidate* global = nullptr; double score = 0.0; size_t sources = 0; };
    std::vector<Candidate> candidates;
    for (const auto& newGlobal : newTarget.analysis.globals)
    {
        size_t matchingSources = 0;
        for (uint64_t oldSource : oldGlobal.sourceFunctions)
        {
            if (oldSource < oldTarget.analysis.module.baseAddress) continue;
            const auto mapped = functionMap.find(oldSource - oldTarget.analysis.module.baseAddress);
            if (mapped == functionMap.end()) continue;
            const uint64_t expected = newTarget.analysis.module.baseAddress + mapped->second;
            if (std::find(newGlobal.sourceFunctions.begin(), newGlobal.sourceFunctions.end(), expected) !=
                newGlobal.sourceFunctions.end())
                ++matchingSources;
        }
        if (matchingSources == 0) continue;
        double score = 0.55 + std::min(0.25, matchingSources * 0.08);
        if (oldGlobal.kind == newGlobal.kind) score += 0.08;
        if (oldGlobal.sectionName == newGlobal.sectionName) score += 0.05;
        if ((oldGlobal.writeCount != 0) == (newGlobal.writeCount != 0)) score += 0.04;
        candidates.push_back({&newGlobal, std::min(1.0, score), matchingSources});
    }
    std::sort(candidates.begin(), candidates.end(), [](const Candidate& left, const Candidate& right) {
        if (left.score != right.score) return left.score > right.score;
        return left.global->rva < right.global->rva;
    });
    if (candidates.empty()) return migration;
    const auto& best = candidates.front();
    migration.newRva = best.global->rva;
    migration.newSupportRva = best.global->accessSites.empty() ? 0 :
        best.global->accessSites.front() - newTarget.analysis.module.baseAddress;
    migration.evidence.push_back(SimilarityEvidence(VersionEvidenceKind::Globals, best.score,
        oldGlobal.sourceFunctions.size(), best.global->sourceFunctions.size(), "matched-function global relationship"));
    migration.evidence.push_back(SimilarityEvidence(VersionEvidenceKind::AccessRole,
        oldGlobal.kind == best.global->kind ? 1.0 : 0.5, oldGlobal.readCount + oldGlobal.writeCount,
        best.global->readCount + best.global->writeCount, "section and read/write role"));
    migration.suggestedState = candidates.size() > 1 && best.score - candidates[1].score <= 0.05
        ? VersionMatchState::Ambiguous : VersionMatchState::StrongCandidate;
    return migration;
}

std::map<uint64_t, uint64_t> BuildFunctionMigrationMap(const VersionComparison& comparison)
{
    return ConfidentFunctionMap(comparison);
}

void MigrateSignatures(VersionComparison& comparison, const VersionAnalysisTarget& oldTarget,
                       const VersionAnalysisTarget& newTarget, const CancellationToken* cancellation)
{
    PatternScanner scanner;
    SignatureEngine engine;
    Disassembler disassembler;
    disassembler.Init(newTarget.analysis.is64Bit);
    std::unordered_map<std::string, PatternScanReport> oldScans;
    std::unordered_map<std::string, PatternScanReport> newScans;
    const auto cachedScan = [&](const SignatureRecord& signature,
                                const VersionAnalysisTarget& target,
                                std::unordered_map<std::string, PatternScanReport>& cache)
        -> const PatternScanReport& {
        const std::string key = SignatureEngine::FormatPattern(signature.pattern);
        const auto existing = cache.find(key);
        if (existing != cache.end()) return existing->second;
        ++comparison.signatureScansPerformed;
        OfflinePatternScanOptions options;
        options.maxResults = 3;
        auto report = scanner.ScanOffline(signature.pattern, target.mappedImage,
            target.analysis.pe, target.rawFileSize, options, cancellation);
        return cache.emplace(key, std::move(report)).first->second;
    };
    for (const auto& signature : oldTarget.analysis.signatures)
    {
        if (cancellation && cancellation->IsCancellationRequested()) return;
        VersionMigrationCandidate migration;
        migration.stableId = "signature:" + signature.stableId;
        migration.kind = VersionMigrationKind::Signature;
        migration.offsetKind = OffsetKind::PatternMatch;
        migration.oldRva = signature.targetOffset;
        if (signature.relationship.kind == SignatureTargetKind::RipRelativeOperand ||
            signature.relationship.kind == SignatureTargetKind::FieldDisplacement)
        {
            const auto& oldScan = cachedScan(signature, oldTarget, oldScans);
            if (oldScan.results.size() == 1)
            {
                const uint64_t oldMatch = oldScan.results.front().address;
                const uint64_t oldMatchRva = oldMatch - oldTarget.analysis.module.baseAddress;
                if (oldMatchRva < oldTarget.mappedImage.size())
                {
                    const size_t oldAvailable = std::min<size_t>(64,
                        oldTarget.mappedImage.size() - oldMatchRva);
                    const auto oldInstructions = disassembler.Disassemble(
                        oldTarget.mappedImage.data() + oldMatchRva, oldAvailable, oldMatch, 16);
                    const auto oldResolved = engine.Resolve(signature, oldMatch, oldInstructions);
                    if (oldResolved.valid)
                    {
                        if (signature.relationship.kind == SignatureTargetKind::FieldDisplacement)
                            migration.oldValue = oldResolved.value;
                        else
                            migration.oldRva = oldResolved.address - oldTarget.analysis.module.baseAddress;
                    }
                }
            }
        }
        const auto& scan = cachedScan(signature, newTarget, newScans);
        migration.evidence.push_back(SimilarityEvidence(VersionEvidenceKind::Signature,
            scan.results.size() == 1 ? 1.0 : 0.0, 1, scan.results.size(),
            scan.error.empty() ? "bounded executable-section scan" : scan.error));
        if (!scan.error.empty() || scan.results.empty())
        {
            migration.suggestedState = VersionMatchState::Unmatched;
            comparison.migrations.push_back(std::move(migration));
            continue;
        }
        if (scan.results.size() > 1 || scan.resultLimitReached)
        {
            migration.suggestedState = VersionMatchState::Ambiguous;
            comparison.migrations.push_back(std::move(migration));
            continue;
        }
        const uint64_t matchAddress = scan.results.front().address;
        if (signature.relationship.kind == SignatureTargetKind::FunctionRva ||
            signature.relationship.kind == SignatureTargetKind::MatchAddress)
        {
            migration.newRva = matchAddress - newTarget.analysis.module.baseAddress;
        }
        else
        {
            const uint64_t matchRva = matchAddress - newTarget.analysis.module.baseAddress;
            if (matchRva >= newTarget.mappedImage.size())
            {
                migration.suggestedState = VersionMatchState::Unmatched;
                comparison.migrations.push_back(std::move(migration));
                continue;
            }
            const size_t available = std::min<size_t>(64, newTarget.mappedImage.size() - matchRva);
            const auto instructions = disassembler.Disassemble(newTarget.mappedImage.data() + matchRva,
                available, matchAddress, 16);
            const auto resolved = engine.Resolve(signature, matchAddress, instructions);
            if (!resolved.valid)
            {
                migration.suggestedState = VersionMatchState::Unmatched;
                comparison.migrations.push_back(std::move(migration));
                continue;
            }
            if (signature.relationship.kind == SignatureTargetKind::FieldDisplacement)
            {
                migration.newValue = resolved.value;
            }
            else
                migration.newRva = resolved.address - newTarget.analysis.module.baseAddress;
        }
        migration.newSupportRva = matchAddress - newTarget.analysis.module.baseAddress;
        migration.suggestedState = VersionMatchState::StrongCandidate;
        comparison.migrations.push_back(std::move(migration));
    }
}

void MigrateFields(VersionComparison& comparison, const VersionAnalysisTarget& oldTarget,
                   const VersionAnalysisTarget& newTarget,
                   const std::map<uint64_t, uint64_t>& functionMap)
{
    using FieldKey = std::tuple<uint64_t, uint8_t, uint8_t, uint8_t, uint8_t>;
    std::map<FieldKey, std::vector<const FieldAccessCandidate*>> newFieldsByRole;
    std::unordered_map<uint64_t, uint64_t> instructionRoles;
    for (const auto& function : oldTarget.analysis.functions)
    {
        for (const auto& block : function.cfg.basicBlocks)
            for (const auto& instruction : block.instructions)
                instructionRoles[instruction.address] = InstructionRole(instruction);
    }
    for (const auto& function : newTarget.analysis.functions)
    {
        for (const auto& block : function.cfg.basicBlocks)
            for (const auto& instruction : block.instructions)
                instructionRoles[instruction.address] = InstructionRole(instruction);
    }
    for (const auto& field : newTarget.analysis.fieldAccesses)
        newFieldsByRole[{field.functionAddress, field.argumentIndex, field.operandSize,
                         static_cast<uint8_t>(field.access),
                         static_cast<uint8_t>(field.originKind)}].push_back(&field);

    std::set<std::string> processed;
    for (const auto& oldField : oldTarget.analysis.fieldAccesses)
    {
        if (oldField.functionAddress < oldTarget.analysis.module.baseAddress) continue;
        const uint64_t oldFunctionRva = oldField.functionAddress - oldTarget.analysis.module.baseAddress;
        const auto mappedFunction = functionMap.find(oldFunctionRva);
        if (mappedFunction == functionMap.end()) continue;
        std::ostringstream stable;
        stable << "field:" << std::hex << oldFunctionRva << ':' << std::dec
               << static_cast<unsigned>(oldField.argumentIndex) << ':' << oldField.displacement << ':'
               << static_cast<unsigned>(oldField.operandSize) << ':' << static_cast<unsigned>(oldField.access);
        if (!processed.insert(stable.str()).second) continue;
        const auto oldRoleFound = instructionRoles.find(oldField.instructionAddress);
        const uint64_t oldRole = oldRoleFound == instructionRoles.end() ? 0 : oldRoleFound->second;
        const uint64_t newFunctionAddress = newTarget.analysis.module.baseAddress + mappedFunction->second;
        struct Candidate { const FieldAccessCandidate* field = nullptr; uint64_t role = 0; double score = 0.0; };
        std::vector<Candidate> candidates;
        const auto newFields = newFieldsByRole.find({newFunctionAddress, oldField.argumentIndex,
            oldField.operandSize, static_cast<uint8_t>(oldField.access),
            static_cast<uint8_t>(oldField.originKind)});
        if (newFields != newFieldsByRole.end())
        {
            for (const auto* newField : newFields->second)
            {
                const auto newRoleFound = instructionRoles.find(newField->instructionAddress);
                const uint64_t newRole = newRoleFound == instructionRoles.end() ? 0 : newRoleFound->second;
                double score = 0.72;
                if (oldRole != 0 && oldRole == newRole) score += 0.20;
                if (oldField.originRegister == newField->originRegister) score += 0.04;
                candidates.push_back({newField, newRole, std::min(1.0, score)});
            }
        }
        std::sort(candidates.begin(), candidates.end(), [](const Candidate& left, const Candidate& right) {
            if (left.score != right.score) return left.score > right.score;
            return left.field->displacement < right.field->displacement;
        });
        VersionMigrationCandidate migration;
        migration.stableId = stable.str();
        migration.kind = VersionMigrationKind::StructureField;
        migration.offsetKind = OffsetKind::StructureField;
        migration.oldRva = oldFunctionRva;
        migration.oldValue = oldField.displacement;
        migration.oldSupportRva = oldField.instructionAddress - oldTarget.analysis.module.baseAddress;
        if (!candidates.empty())
        {
            migration.newRva = mappedFunction->second;
            migration.newValue = candidates.front().field->displacement;
            migration.newSupportRva = candidates.front().field->instructionAddress -
                newTarget.analysis.module.baseAddress;
            migration.evidence.push_back(SimilarityEvidence(VersionEvidenceKind::FieldProvenance,
                candidates.front().score, oldField.operandSize, candidates.front().field->operandSize,
                "same matched function, argument provenance, access, width, and instruction role"));
            migration.suggestedState = candidates.size() > 1 && candidates[0].score - candidates[1].score <= 0.05
                ? VersionMatchState::Ambiguous : VersionMatchState::StrongCandidate;
        }
        comparison.migrations.push_back(std::move(migration));
    }
}

const VersionMigrationCandidate* FindMigration(const VersionComparison& comparison,
                                               VersionMigrationKind kind, uint64_t oldRva,
                                               int64_t oldValue = 0)
{
    const auto found = std::find_if(comparison.migrations.begin(), comparison.migrations.end(),
        [&](const VersionMigrationCandidate& migration) {
            return migration.kind == kind && migration.oldRva == oldRva &&
                (kind != VersionMigrationKind::StructureField || migration.oldValue == oldValue);
        });
    return found == comparison.migrations.end() ? nullptr : &*found;
}

void MigrateOffsets(VersionComparison& comparison, const VersionAnalysisTarget& oldTarget,
                    const VersionAnalysisTarget& newTarget,
                    const std::map<uint64_t, uint64_t>& functionMap)
{
    for (const auto& offset : oldTarget.analysis.offsets)
    {
        VersionMigrationCandidate migration;
        migration.stableId = "offset:" + offset.stableId;
        migration.kind = VersionMigrationKind::Offset;
        migration.offsetKind = offset.kind;
        migration.oldRva = offset.rva;
        migration.oldValue = offset.fieldOffset;
        if (offset.kind == OffsetKind::ExportRva)
        {
            const auto exported = std::find_if(newTarget.analysis.offsets.begin(),
                newTarget.analysis.offsets.end(), [&](const OffsetRecord& candidate) {
                    return candidate.kind == OffsetKind::ExportRva && !offset.name.empty() &&
                        candidate.name == offset.name;
                });
            if (exported != newTarget.analysis.offsets.end())
            {
                migration.newRva = exported->rva;
                migration.suggestedState = VersionMatchState::Exact;
                migration.evidence.push_back(SimilarityEvidence(VersionEvidenceKind::ExportIdentity,
                    1.0, 1, 1, "exact PE export identity"));
            }
            else
            {
                const auto mapped = functionMap.find(offset.rva);
                if (mapped != functionMap.end())
                {
                    migration.newRva = mapped->second;
                    migration.suggestedState = VersionMatchState::StrongCandidate;
                    migration.evidence.push_back(SimilarityEvidence(VersionEvidenceKind::NormalizedCode,
                        1.0, 1, 1, "export fallback follows a confident function mapping"));
                }
            }
        }
        else if (offset.kind == OffsetKind::FunctionRva)
        {
            const auto mapped = functionMap.find(offset.rva);
            if (mapped != functionMap.end())
            {
                migration.newRva = mapped->second;
                migration.suggestedState = VersionMatchState::StrongCandidate;
                migration.evidence.push_back(SimilarityEvidence(VersionEvidenceKind::NormalizedCode,
                    1.0, 1, 1, "typed offset follows a confident function mapping"));
            }
        }
        else if (offset.kind == OffsetKind::GlobalRva)
        {
            if (const auto* global = FindMigration(comparison, VersionMigrationKind::Global, offset.rva))
            {
                migration.newRva = global->newRva;
                migration.suggestedState = global->suggestedState;
                migration.evidence = global->evidence;
            }
        }
        else if (offset.kind == OffsetKind::StructureField)
        {
            const uint64_t functionRva = offset.sourceFunction >= oldTarget.analysis.module.baseAddress
                ? offset.sourceFunction - oldTarget.analysis.module.baseAddress : offset.sourceFunction;
            if (const auto* field = FindMigration(comparison, VersionMigrationKind::StructureField,
                                                   functionRva, offset.fieldOffset))
            {
                migration.newRva = field->newRva;
                migration.newValue = field->newValue;
                migration.suggestedState = field->suggestedState;
                migration.evidence = field->evidence;
            }
        }
        else if (offset.kind == OffsetKind::PatternMatch)
        {
            const auto found = std::find_if(comparison.migrations.begin(), comparison.migrations.end(),
                [&](const VersionMigrationCandidate& candidate) {
                    return candidate.kind == VersionMigrationKind::Signature &&
                        candidate.stableId.find(offset.stableId) != std::string::npos;
                });
            if (found != comparison.migrations.end())
            {
                migration.newRva = found->newRva;
                migration.newValue = found->newValue;
                migration.suggestedState = found->suggestedState;
                migration.evidence = found->evidence;
            }
        }
        else if (offset.kind == OffsetKind::ImportRva || offset.kind == OffsetKind::UserDefined)
        {
            const auto found = std::find_if(newTarget.analysis.offsets.begin(), newTarget.analysis.offsets.end(),
                [&](const OffsetRecord& candidate) {
                    return candidate.kind == offset.kind &&
                        (candidate.stableId == offset.stableId ||
                         (offset.kind == OffsetKind::ImportRva && !offset.name.empty() && candidate.name == offset.name));
                });
            if (found != newTarget.analysis.offsets.end())
            {
                migration.newRva = found->rva;
                migration.newValue = found->fieldOffset;
                migration.suggestedState = VersionMatchState::Candidate;
                migration.evidence.push_back(SimilarityEvidence(offset.kind == OffsetKind::ImportRva
                    ? VersionEvidenceKind::Imports : VersionEvidenceKind::AccessRole,
                    0.65, 1, 1, offset.kind == OffsetKind::ImportRva
                        ? "matching PE import identity" : "stable typed identifier; explicit review required"));
            }
        }
        comparison.migrations.push_back(std::move(migration));
    }
}

} // namespace

VersionComparison VersionIntelligenceEngine::Compare(const VersionAnalysisTarget& oldTarget,
                                                      const VersionAnalysisTarget& newTarget,
                                                      const CancellationToken* cancellation,
                                                      const ProgressCallback& progress) const
{
    constexpr size_t kMaximumScoredCandidatePairs = 2000000;
    VersionComparison comparison;
    comparison.oldTarget = oldTarget.identity;
    comparison.newTarget = newTarget.identity;
    if (oldTarget.analysis.functions.empty() || newTarget.analysis.functions.empty())
    {
        comparison.error = "Both targets require completed function analysis";
        return comparison;
    }
    if (oldTarget.identity.architecture != newTarget.identity.architecture)
    {
        comparison.error = "Version Intelligence requires matching target architectures";
        return comparison;
    }
    const auto cancelled = [&] {
        if (cancellation && cancellation->IsCancellationRequested())
        {
            comparison.cancelled = true;
            return true;
        }
        return false;
    };

    if (progress) progress(0.05f);
    const auto oldFingerprints = BuildFingerprints(oldTarget.analysis);
    if (cancelled()) return comparison;
    if (progress) progress(0.15f);
    const auto newFingerprints = BuildFingerprints(newTarget.analysis);
    if (cancelled()) return comparison;
    const auto oldIndexes = BuildIndexes(oldFingerprints);
    const auto newIndexes = BuildIndexes(newFingerprints);
    if (progress) progress(0.25f);

    for (size_t oldIndex = 0; oldIndex < oldFingerprints.size(); ++oldIndex)
    {
        if (cancelled()) return comparison;
        const auto& oldFingerprint = oldFingerprints[oldIndex];
        VersionFunctionMatch match;
        match.oldRva = oldFingerprint.functionRva;
        match.oldName = oldTarget.analysis.functions[oldIndex].name;
        match.stableId = "function:" + Hex(match.oldRva);
        bool candidateBudgetReached = false;
        const auto candidates = CandidateIndexes(oldFingerprint, newIndexes,
                                                  candidateBudgetReached);
        comparison.candidateBudgetReached = comparison.candidateBudgetReached ||
                                            candidateBudgetReached;
        comparison.indexedCandidatePairs += candidates.size();
        bool functionBudgetReached = candidateBudgetReached;
        for (size_t newIndex : candidates)
        {
            if (comparison.scoredCandidatePairs >= kMaximumScoredCandidatePairs)
            {
                comparison.candidateBudgetReached = true;
                functionBudgetReached = true;
                break;
            }
            if (newIndex >= newFingerprints.size()) continue;
            const auto& newFingerprint = newFingerprints[newIndex];
            const auto similarity = EvaluateFunctionFingerprints(oldFingerprint, newFingerprint);
            ++comparison.scoredCandidatePairs;
            if (similarity.total < 0.40 && !similarity.exactNormalized) continue;
            VersionFunctionCandidate candidate;
            candidate.newRva = newFingerprint.functionRva;
            candidate.newName = newTarget.analysis.functions[newIndex].name;
            candidate.similarityScore = similarity.total;
            candidate.suggestedState = CandidateState(oldFingerprint, newFingerprint, similarity);
            candidate.evidence = BuildEvidence(oldFingerprint, newFingerprint, similarity);
            candidate.changes = BuildChanges(oldFingerprint, newFingerprint);
            match.candidates.push_back(std::move(candidate));
        }
        std::sort(match.candidates.begin(), match.candidates.end(), [](const auto& left, const auto& right) {
            if (left.similarityScore != right.similarityScore) return left.similarityScore > right.similarityScore;
            return left.newRva < right.newRva;
        });
        if (functionBudgetReached)
            match.suggestedState = match.candidates.empty()
                ? VersionMatchState::Unmatched : VersionMatchState::Ambiguous;
        else if (match.candidates.empty())
            match.suggestedState = VersionMatchState::Removed;
        else
        {
            const bool exactUniqueOnBothSides = match.candidates.front().suggestedState == VersionMatchState::Exact &&
                oldIndexes.normalized.at(oldFingerprint.normalizedHash).size() == 1 &&
                newIndexes.normalized.at(oldFingerprint.normalizedHash).size() == 1;
            const bool ambiguous = match.candidates.size() > 1 &&
                match.candidates[0].similarityScore - match.candidates[1].similarityScore <= 0.05;
            match.suggestedState = ambiguous ? VersionMatchState::Ambiguous :
                exactUniqueOnBothSides ? VersionMatchState::Exact :
                match.candidates.front().suggestedState == VersionMatchState::StrongCandidate
                    ? VersionMatchState::StrongCandidate : VersionMatchState::Candidate;
        }
        comparison.functions.push_back(std::move(match));
        if (progress) progress(0.25f + 0.35f * static_cast<float>(oldIndex + 1) /
            static_cast<float>(oldFingerprints.size()));
    }

    RefineWithMatchedCallees(comparison, oldFingerprints, newFingerprints);
    const auto functionMap = BuildFunctionMigrationMap(comparison);
    std::set<uint64_t> matchedNew;
    for (const auto& [oldRva, newRva] : functionMap)
    {
        (void)oldRva;
        matchedNew.insert(newRva);
    }
    for (const auto& fingerprint : newFingerprints)
        if (matchedNew.find(fingerprint.functionRva) == matchedNew.end())
            comparison.newFunctionRvas.push_back(fingerprint.functionRva);
    if (progress) progress(0.65f);

    for (const auto& global : oldTarget.analysis.globals)
    {
        if (cancelled()) return comparison;
        comparison.migrations.push_back(MigrateGlobal(global, oldTarget, newTarget, functionMap));
    }
    if (progress) progress(0.72f);
    MigrateSignatures(comparison, oldTarget, newTarget, cancellation);
    if (cancelled()) return comparison;
    if (progress) progress(0.84f);
    MigrateFields(comparison, oldTarget, newTarget, functionMap);
    MigrateOffsets(comparison, oldTarget, newTarget, functionMap);
    if (progress) progress(1.0f);
    return comparison;
}

VersionMatchState EffectiveState(VersionMatchState suggested, VersionDecision decision)
{
    if (decision == VersionDecision::Accepted) return VersionMatchState::Accepted;
    if (decision == VersionDecision::Rejected) return VersionMatchState::Rejected;
    return suggested;
}

const char* VersionMatchStateName(VersionMatchState state)
{
    switch (state)
    {
    case VersionMatchState::Exact: return "Exact";
    case VersionMatchState::StrongCandidate: return "StrongCandidate";
    case VersionMatchState::Candidate: return "Candidate";
    case VersionMatchState::Ambiguous: return "Ambiguous";
    case VersionMatchState::Removed: return "Removed";
    case VersionMatchState::New: return "New";
    case VersionMatchState::Rejected: return "Rejected";
    case VersionMatchState::Accepted: return "Accepted";
    default: return "Unmatched";
    }
}

const char* VersionDecisionName(VersionDecision decision)
{
    switch (decision)
    {
    case VersionDecision::Accepted: return "Accepted";
    case VersionDecision::Rejected: return "Rejected";
    default: return "None";
    }
}

const char* VersionEvidenceKindName(VersionEvidenceKind kind)
{
    switch (kind)
    {
    case VersionEvidenceKind::Cfg: return "CFG";
    case VersionEvidenceKind::Strings: return "Strings";
    case VersionEvidenceKind::Imports: return "Imports";
    case VersionEvidenceKind::Globals: return "Globals";
    case VersionEvidenceKind::Calls: return "Calls";
    case VersionEvidenceKind::MatchedCallees: return "MatchedCallees";
    case VersionEvidenceKind::Signature: return "Signature";
    case VersionEvidenceKind::RuntimeBoundary: return "RuntimeBoundary";
    case VersionEvidenceKind::Symbol: return "Symbol";
    case VersionEvidenceKind::FieldProvenance: return "FieldProvenance";
    case VersionEvidenceKind::ExportIdentity: return "ExportIdentity";
    case VersionEvidenceKind::AccessRole: return "AccessRole";
    case VersionEvidenceKind::OrderedCode: return "OrderedCode";
    default: return "NormalizedCode";
    }
}

const char* VersionMigrationKindName(VersionMigrationKind kind)
{
    switch (kind)
    {
    case VersionMigrationKind::Global: return "Global";
    case VersionMigrationKind::Signature: return "Signature";
    case VersionMigrationKind::StructureField: return "StructureField";
    default: return "Offset";
    }
}

bool ParseVersionMatchState(const std::string& value, VersionMatchState& state)
{
    for (VersionMatchState candidate : {VersionMatchState::Exact, VersionMatchState::StrongCandidate,
        VersionMatchState::Candidate, VersionMatchState::Ambiguous, VersionMatchState::Unmatched,
        VersionMatchState::Removed, VersionMatchState::New, VersionMatchState::Rejected,
        VersionMatchState::Accepted})
    {
        if (value == VersionMatchStateName(candidate)) { state = candidate; return true; }
    }
    return false;
}

bool ParseVersionDecision(const std::string& value, VersionDecision& decision)
{
    for (VersionDecision candidate : {VersionDecision::None, VersionDecision::Accepted,
                                      VersionDecision::Rejected})
    {
        if (value == VersionDecisionName(candidate)) { decision = candidate; return true; }
    }
    return false;
}

bool ParseVersionEvidenceKind(const std::string& value, VersionEvidenceKind& kind)
{
    for (VersionEvidenceKind candidate : {VersionEvidenceKind::NormalizedCode, VersionEvidenceKind::Cfg,
        VersionEvidenceKind::Strings, VersionEvidenceKind::Imports, VersionEvidenceKind::Globals,
        VersionEvidenceKind::Calls, VersionEvidenceKind::MatchedCallees, VersionEvidenceKind::Signature,
        VersionEvidenceKind::RuntimeBoundary, VersionEvidenceKind::Symbol,
        VersionEvidenceKind::FieldProvenance, VersionEvidenceKind::ExportIdentity,
        VersionEvidenceKind::AccessRole, VersionEvidenceKind::OrderedCode})
    {
        if (value == VersionEvidenceKindName(candidate)) { kind = candidate; return true; }
    }
    return false;
}

bool ParseVersionMigrationKind(const std::string& value, VersionMigrationKind& kind)
{
    for (VersionMigrationKind candidate : {VersionMigrationKind::Global, VersionMigrationKind::Signature,
        VersionMigrationKind::Offset, VersionMigrationKind::StructureField})
    {
        if (value == VersionMigrationKindName(candidate)) { kind = candidate; return true; }
    }
    return false;
}

} // namespace openreverse
