#include "analysis_session.h"

#include <algorithm>
#include <sstream>

namespace openreverse {

namespace {

uint64_t ToRva(uint64_t address, uint64_t imageBase)
{
    return address >= imageBase ? address - imageBase : address;
}

uint64_t RebaseAddress(uint64_t address, uint64_t oldBase, uint64_t newBase)
{
    return address >= oldBase ? newBase + (address - oldBase) : address;
}

ProjectStructure CaptureStructure(const StructureCandidate& source, uint64_t imageBase)
{
    ProjectStructure structure;
    structure.name = source.name;
    structure.sourceFunctionRva = ToRva(source.functionAddress, imageBase);
    structure.baseRegister = source.baseRegister;
    structure.argumentIndex = source.argumentIndex;
    structure.estimatedSize = source.estimatedSize;
    structure.evidenceScore = source.evidenceScore;
    structure.evidence = source.evidence;
    std::ostringstream stableId;
    stableId << "structure:" << std::hex << structure.sourceFunctionRva << ":"
             << static_cast<unsigned>(structure.argumentIndex) << ":" << structure.baseRegister;
    structure.stableId = stableId.str();
    for (const auto& fieldSource : source.fields)
    {
        ProjectStructureField field;
        field.offset = fieldSource.offset;
        field.size = fieldSource.size;
        field.readCount = fieldSource.readCount;
        field.writeCount = fieldSource.writeCount;
        field.addressCount = fieldSource.addressCount;
        structure.fields.push_back(std::move(field));
    }
    return structure;
}

} // namespace

void AnalysisSession::ClearAnalysis()
{
    database_.Clear();
}

void AnalysisSession::ClearProject()
{
    project_ = {};
    projectPath_.clear();
    hasProject_ = false;
    dirty_ = false;
    requiresSaveAs_ = false;
    restoreTargetBoundState_ = false;
}

void AnalysisSession::SetLoadedProject(OpenReverseProject project, const std::string& path,
                                       bool restoreTargetBoundState)
{
    project_ = std::move(project);
    projectPath_ = path;
    hasProject_ = true;
    dirty_ = false;
    requiresSaveAs_ = !restoreTargetBoundState;
    restoreTargetBoundState_ = restoreTargetBoundState;
    if (!restoreTargetBoundState_)
    {
        project_.analysis = {};
        project_.user.functions.clear();
        project_.user.bookmarks.clear();
        project_.user.structures.clear();
        project_.user.migrations.clear();
        project_.hasVersionComparison = false;
        project_.versionComparison = {};
    }
}

void AnalysisSession::MarkSaved(OpenReverseProject project, const std::string& path)
{
    project_ = std::move(project);
    projectPath_ = path;
    hasProject_ = true;
    dirty_ = false;
    requiresSaveAs_ = false;
    restoreTargetBoundState_ = true;
}

void AnalysisSession::MarkDirty()
{
    hasProject_ = true;
    dirty_ = true;
    restoreTargetBoundState_ = true;
}

OpenReverseProject AnalysisSession::BuildSnapshot(const ProjectTarget& target,
                                                  const ModuleAnalysisState& analysis,
                                                  const ProjectUiState& ui) const
{
    OpenReverseProject snapshot;
    snapshot.version = kOpenReverseProjectVersion;
    snapshot.target = target;
    snapshot.ui = ui;
    if (hasProject_) snapshot.user = project_.user;
    if (hasProject_ && project_.hasVersionComparison)
    {
        snapshot.hasVersionComparison = true;
        snapshot.versionComparison = project_.versionComparison;
    }
    if (hasProject_) snapshot.extensionState = project_.extensionState;
    snapshot.analysis.offsets = analysis.offsets;
    snapshot.analysis.signatures = analysis.signatures;
    snapshot.analysis.structures.reserve(analysis.structures.size());
    for (const auto& structure : analysis.structures)
        snapshot.analysis.structures.push_back(CaptureStructure(structure, analysis.module.baseAddress));
    return snapshot;
}

void AnalysisSession::ApplyPersistedAnalysis(ModuleAnalysisResult& result) const
{
    if (!hasProject_ || !restoreTargetBoundState_) return;
    const uint64_t oldBase = project_.target.imageBase;
    const uint64_t newBase = result.module.baseAddress;

    for (const auto& storedOffset : project_.analysis.offsets)
    {
        auto existing = std::find_if(result.offsets.begin(), result.offsets.end(),
            [&](const OffsetRecord& value) { return value.stableId == storedOffset.stableId; });
        OffsetRecord restored = storedOffset;
        if (restored.rva != 0) restored.address = newBase + restored.rva;
        restored.sourceFunction = RebaseAddress(restored.sourceFunction, oldBase, newBase);
        restored.sourceInstruction = RebaseAddress(restored.sourceInstruction, oldBase, newBase);
        if (existing == result.offsets.end())
            result.offsets.push_back(std::move(restored));
        else if (storedOffset.kind == OffsetKind::UserDefined)
            *existing = std::move(restored);
    }

    for (const auto& storedSignature : project_.analysis.signatures)
    {
        const auto existing = std::find_if(result.signatures.begin(), result.signatures.end(),
            [&](const SignatureRecord& value) { return value.stableId == storedSignature.stableId; });
        if (existing != result.signatures.end()) continue;
        SignatureRecord restored = storedSignature;
        restored.targetFunction = RebaseAddress(restored.targetFunction, oldBase, newBase);
        result.signatures.push_back(std::move(restored));
    }
}

const ProjectFunctionAnnotation* AnalysisSession::FindFunctionAnnotation(uint64_t rva) const
{
    if (!restoreTargetBoundState_) return nullptr;
    const auto found = std::find_if(project_.user.functions.begin(), project_.user.functions.end(),
        [&](const ProjectFunctionAnnotation& annotation) { return annotation.rva == rva; });
    return found == project_.user.functions.end() ? nullptr : &*found;
}

void AnalysisSession::SetFunctionAnnotation(uint64_t rva, const std::string& name,
                                            const std::string& comment)
{
    auto found = std::find_if(project_.user.functions.begin(), project_.user.functions.end(),
        [&](const ProjectFunctionAnnotation& annotation) { return annotation.rva == rva; });
    if (found == project_.user.functions.end())
        project_.user.functions.push_back({rva, name, comment});
    else
    {
        found->name = name;
        found->comment = comment;
    }
    hasProject_ = true;
    restoreTargetBoundState_ = true;
    dirty_ = true;
}

void AnalysisSession::RemoveFunctionAnnotation(uint64_t rva)
{
    const auto before = project_.user.functions.size();
    project_.user.functions.erase(
        std::remove_if(project_.user.functions.begin(), project_.user.functions.end(),
            [&](const ProjectFunctionAnnotation& annotation) { return annotation.rva == rva; }),
        project_.user.functions.end());
    if (project_.user.functions.size() != before) dirty_ = true;
}

void AnalysisSession::AddBookmark(ProjectBookmark bookmark)
{
    project_.user.bookmarks.push_back(std::move(bookmark));
    hasProject_ = true;
    restoreTargetBoundState_ = true;
    dirty_ = true;
}

void AnalysisSession::RemoveBookmark(size_t index)
{
    if (index >= project_.user.bookmarks.size()) return;
    project_.user.bookmarks.erase(project_.user.bookmarks.begin() + index);
    dirty_ = true;
}

const VersionComparison* AnalysisSession::VersionIntelligence() const
{
    return hasProject_ && project_.hasVersionComparison ? &project_.versionComparison : nullptr;
}

void AnalysisSession::SetVersionComparison(VersionComparison comparison)
{
    if (project_.hasVersionComparison)
    {
        const auto previousFunction = [&](const std::string& stableId) -> const VersionFunctionMatch* {
            for (const auto& function : project_.versionComparison.functions)
                if (function.stableId == stableId) return &function;
            return nullptr;
        };
        const auto previousMigration = [&](const std::string& stableId) -> const VersionMigrationCandidate* {
            for (const auto& migration : project_.versionComparison.migrations)
                if (migration.stableId == stableId) return &migration;
            return nullptr;
        };
        for (auto& function : comparison.functions)
        {
            if (const auto* previous = previousFunction(function.stableId))
            {
                const bool acceptedCandidateStillExists = previous->decision != VersionDecision::Accepted ||
                    std::any_of(function.candidates.begin(), function.candidates.end(),
                        [&](const VersionFunctionCandidate& candidate) {
                            return candidate.newRva == previous->decisionNewRva;
                        });
                if (acceptedCandidateStillExists)
                {
                    function.decision = previous->decision;
                    function.decisionNewRva = previous->decisionNewRva;
                }
            }
        }
        for (auto& migration : comparison.migrations)
        {
            if (const auto* previous = previousMigration(migration.stableId))
            {
                const bool acceptedCandidateUnchanged = previous->decision != VersionDecision::Accepted ||
                    (previous->newRva == migration.newRva && previous->newValue == migration.newValue);
                if (acceptedCandidateUnchanged) migration.decision = previous->decision;
            }
        }
    }
    project_.versionComparison = std::move(comparison);
    project_.hasVersionComparison = true;
    MarkDirty();
}

bool AnalysisSession::SetVersionDecision(const std::string& stableId, VersionDecision decision,
                                         uint64_t selectedNewRva)
{
    if (!project_.hasVersionComparison) return false;
    VersionMigrationCandidate* selectedMigration = nullptr;
    VersionFunctionMatch* selectedFunction = nullptr;
    bool changed = false;
    bool found = false;
    for (auto& function : project_.versionComparison.functions)
    {
        if (function.stableId != stableId) continue;
        found = true;
        if (decision == VersionDecision::Accepted &&
            std::none_of(function.candidates.begin(), function.candidates.end(),
                [&](const VersionFunctionCandidate& candidate) {
                    return candidate.newRva == selectedNewRva;
                }))
            return false;
        changed = function.decision != decision;
        if (decision == VersionDecision::Accepted && function.decisionNewRva != selectedNewRva)
            changed = true;
        function.decision = decision;
        function.decisionNewRva = decision == VersionDecision::Accepted ? selectedNewRva : 0;
        selectedFunction = &function;
        break;
    }
    if (!found)
    {
        for (auto& migration : project_.versionComparison.migrations)
        {
            if (migration.stableId != stableId) continue;
            found = true;
            const bool actionable = migration.suggestedState == VersionMatchState::Exact ||
                migration.suggestedState == VersionMatchState::StrongCandidate ||
                migration.suggestedState == VersionMatchState::Candidate;
            if (decision == VersionDecision::Accepted && !actionable) return false;
            changed = migration.decision != decision;
            migration.decision = decision;
            selectedMigration = &migration;
            break;
        }
    }
    if (!found || !changed) return false;

    const std::string decisionId = "version-intelligence:" + stableId;
    project_.user.migrations.erase(std::remove_if(project_.user.migrations.begin(),
        project_.user.migrations.end(), [&](const ProjectMigrationDecision& migration) {
            return migration.stableId == decisionId;
        }), project_.user.migrations.end());
    if (decision != VersionDecision::None)
    {
        ProjectMigrationDecision persisted;
        persisted.stableId = decisionId;
        persisted.decision = decision == VersionDecision::Accepted
            ? ProjectMigrationDecisionKind::Accepted : ProjectMigrationDecisionKind::Rejected;
        if (selectedMigration)
        {
            persisted.kind = selectedMigration->offsetKind;
            persisted.oldRva = selectedMigration->oldRva;
            persisted.newRva = selectedMigration->newRva;
            persisted.oldValue = selectedMigration->oldValue;
            persisted.newValue = selectedMigration->newValue;
            for (const auto& evidence : selectedMigration->evidence)
                persisted.evidence.push_back(std::string(VersionEvidenceKindName(evidence.kind)) +
                    ": " + evidence.detail);
        }
        else
        {
            persisted.kind = OffsetKind::FunctionRva;
            if (selectedFunction)
            {
                persisted.oldRva = selectedFunction->oldRva;
                persisted.newRva = selectedFunction->decisionNewRva;
            }
        }
        project_.user.migrations.push_back(std::move(persisted));
    }
    MarkDirty();
    return true;
}

const std::string* AnalysisSession::ExtensionState(const std::string& extensionId) const
{
    if (!hasProject_) return nullptr;
    const auto found = project_.extensionState.find(extensionId);
    return found == project_.extensionState.end() ? nullptr : &found->second;
}

bool AnalysisSession::SetExtensionState(const std::string& extensionId,
                                        const std::string& jsonObject,
                                        std::string& error)
{
    if (!hasProject_)
    {
        error = "No active OpenReverse project";
        return false;
    }
    std::string canonical;
    if (!ProjectStore::ValidateExtensionState(extensionId, jsonObject, canonical, error))
        return false;
    const auto found = project_.extensionState.find(extensionId);
    if (found != project_.extensionState.end() && found->second == canonical) return true;
    project_.extensionState[extensionId] = std::move(canonical);
    MarkDirty();
    return true;
}

} // namespace openreverse
