#pragma once

#include "core/analysis_database.h"
#include "core/binary_diff.h"
#include "core/cancellation.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace openreverse {

constexpr uint32_t kVersionIntelligenceAlgorithmVersion = 2;

enum class VersionMatchState {
    Exact,
    StrongCandidate,
    Candidate,
    Ambiguous,
    Unmatched,
    Removed,
    New,
    Rejected,
    Accepted
};

enum class VersionDecision {
    None,
    Accepted,
    Rejected
};

enum class VersionEvidenceKind {
    NormalizedCode,
    Cfg,
    Strings,
    Imports,
    Globals,
    Calls,
    MatchedCallees,
    Signature,
    RuntimeBoundary,
    Symbol,
    FieldProvenance,
    ExportIdentity,
    AccessRole,
    OrderedCode
};

enum class VersionMigrationKind {
    Global,
    Signature,
    Offset,
    StructureField
};

struct VersionTargetIdentity {
    std::string name;
    std::string path;
    std::string sha256;
    std::string architecture;
    uint32_t peTimestamp = 0;
    uint32_t sizeOfImage = 0;
    uint64_t imageBase = 0;
};

struct VersionEvidence {
    VersionEvidenceKind kind = VersionEvidenceKind::NormalizedCode;
    double score = 0.0;
    uint32_t oldCount = 0;
    uint32_t newCount = 0;
    std::string detail;
};

struct FunctionChangeSummary {
    int64_t instructionDelta = 0;
    int64_t basicBlockDelta = 0;
    int64_t edgeDelta = 0;
    int64_t callDelta = 0;
    std::vector<std::string> addedStrings;
    std::vector<std::string> removedStrings;
    std::vector<std::string> addedImports;
    std::vector<std::string> removedImports;
    std::vector<std::string> addedGlobals;
    std::vector<std::string> removedGlobals;
    std::vector<std::string> addedFields;
    std::vector<std::string> removedFields;
};

struct VersionFunctionCandidate {
    uint64_t newRva = 0;
    std::string newName;
    double similarityScore = 0.0;
    VersionMatchState suggestedState = VersionMatchState::Candidate;
    std::vector<VersionEvidence> evidence;
    FunctionChangeSummary changes;
};

struct VersionFunctionMatch {
    std::string stableId;
    uint64_t oldRva = 0;
    std::string oldName;
    VersionMatchState suggestedState = VersionMatchState::Unmatched;
    VersionDecision decision = VersionDecision::None;
    uint64_t decisionNewRva = 0;
    std::vector<VersionFunctionCandidate> candidates;
};

struct VersionMigrationCandidate {
    std::string stableId;
    VersionMigrationKind kind = VersionMigrationKind::Offset;
    OffsetKind offsetKind = OffsetKind::UserDefined;
    uint64_t oldRva = 0;
    uint64_t newRva = 0;
    int64_t oldValue = 0;
    int64_t newValue = 0;
    uint64_t oldSupportRva = 0;
    uint64_t newSupportRva = 0;
    VersionMatchState suggestedState = VersionMatchState::Unmatched;
    VersionDecision decision = VersionDecision::None;
    std::vector<VersionEvidence> evidence;
};

struct VersionComparison {
    uint32_t algorithmVersion = kVersionIntelligenceAlgorithmVersion;
    VersionTargetIdentity oldTarget;
    VersionTargetIdentity newTarget;
    std::vector<VersionFunctionMatch> functions;
    std::vector<uint64_t> newFunctionRvas;
    std::vector<VersionMigrationCandidate> migrations;
    size_t indexedCandidatePairs = 0;
    size_t scoredCandidatePairs = 0;
    size_t signatureScansPerformed = 0;
    bool candidateBudgetReached = false;
    bool cancelled = false;
    std::string error;
};

struct VersionAnalysisTarget {
    VersionTargetIdentity identity;
    ModuleAnalysisState analysis;
    std::vector<uint8_t> mappedImage;
    size_t rawFileSize = 0;
};

class VersionIntelligenceEngine {
public:
    using ProgressCallback = std::function<void(float)>;

    VersionComparison Compare(const VersionAnalysisTarget& oldTarget,
                              const VersionAnalysisTarget& newTarget,
                              const CancellationToken* cancellation = nullptr,
                              const ProgressCallback& progress = {}) const;
};

VersionMatchState EffectiveState(VersionMatchState suggested, VersionDecision decision);
const char* VersionMatchStateName(VersionMatchState state);
const char* VersionDecisionName(VersionDecision decision);
const char* VersionEvidenceKindName(VersionEvidenceKind kind);
const char* VersionMigrationKindName(VersionMigrationKind kind);
bool ParseVersionMatchState(const std::string& value, VersionMatchState& state);
bool ParseVersionDecision(const std::string& value, VersionDecision& decision);
bool ParseVersionEvidenceKind(const std::string& value, VersionEvidenceKind& kind);
bool ParseVersionMigrationKind(const std::string& value, VersionMigrationKind& kind);

} // namespace openreverse
