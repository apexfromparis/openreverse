#include "version_intelligence_panel.h"

#include "app/application.h"
#include "analysis/module_analysis.h"
#include "analysis/pe_parser.h"
#include "workspace/project.h"
#include "ui/workspace_ui.h"
#include "utils/helpers.h"

#include <commdlg.h>
#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>

namespace openreverse { namespace panels {

namespace {

struct ComparisonJobResult {
    VersionComparison comparison;
    VersionAnalysisTarget oldTarget;
};

std::string LowerExtension(const std::string& path)
{
    std::string extension = std::filesystem::path(path).extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(),
        [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return extension;
}

VersionAnalysisTarget CurrentTarget(const Application& app, const ModuleAnalysisState& analysis)
{
    VersionAnalysisTarget target;
    target.analysis = analysis;
    target.mappedImage = app.offlineImageBuffer;
    target.rawFileSize = app.offlineFileBuffer.size();
    target.identity.name = analysis.module.name;
    target.identity.path = app.loadedFilePath;
    target.identity.sha256 = analysis.identity.sha256;
    target.identity.architecture = analysis.is64Bit ? "x64" : "x86";
    target.identity.peTimestamp = analysis.pe.timestamp;
    target.identity.sizeOfImage = analysis.pe.sizeOfImage;
    target.identity.imageBase = analysis.module.baseAddress;
    return target;
}

bool LoadOldPeTarget(const std::string& selectedPath, VersionAnalysisTarget& target,
                     std::string& error, const CancellationToken& cancellation,
                     const AnalysisScheduler::ProgressCallback& progress)
{
    std::string binaryPath = selectedPath;
    if (LowerExtension(selectedPath) == ".orev")
    {
        OpenReverseProject project;
        if (!ProjectStore::Load(selectedPath, project, error)) return false;
        if (project.target.kind != ProjectTargetKind::PEFile)
        {
            error = "Version Intelligence currently accepts PE-backed .orev projects as the old target";
            return false;
        }
        const auto verification = ProjectStore::VerifyTarget(project);
        if (verification.status != ProjectTargetVerificationStatus::Match)
        {
            error = verification.error.empty()
                ? "The old project target identity could not be verified" : verification.error;
            return false;
        }
        binaryPath = project.target.path;
    }

    PEParser parser;
    std::vector<uint8_t> raw;
    const PEInfo pe = parser.ParseFile(binaryPath, raw);
    if (!pe.valid || raw.empty())
    {
        error = "The selected old target is not a valid PE32/PE32+ binary";
        return false;
    }
    std::vector<uint8_t> mapped;
    if (!PEParser::BuildMappedImage(raw, pe, mapped))
    {
        error = "The old target could not be mapped into its RVA address space";
        return false;
    }
    const std::string name = std::filesystem::path(binaryPath).filename().string();
    ModuleInfo module{name, binaryPath, pe.imageBase, pe.sizeOfImage};
    ModuleAnalysisOptions options;
    options.maxCodeBytes = 16ULL * 1024ULL * 1024ULL;
    options.maxStringBytes = 64ULL * 1024ULL * 1024ULL;
    ModuleAnalysisPipeline pipeline;
    const auto analysis = pipeline.AnalyzeMappedImage(mapped, raw.size(), module, pe, options,
        &cancellation, [&](float value) { if (progress) progress(value * 0.55f); });
    if (!analysis.success)
    {
        error = analysis.cancelled ? "Old-target analysis was cancelled" : analysis.error;
        return false;
    }
    ModuleIdentity identity;
    if (!ComputeModuleIdentity(raw, pe, name, identity, error)) return false;

    target.identity = {name, binaryPath, identity.sha256, pe.is64bit ? "x64" : "x86",
        pe.timestamp, pe.sizeOfImage, pe.imageBase};
    target.analysis.module = analysis.module;
    target.analysis.is64Bit = pe.is64bit;
    target.analysis.pe = analysis.pe;
    target.analysis.functions = analysis.functions;
    target.analysis.xrefs = analysis.xrefs;
    target.analysis.strings = analysis.strings;
    target.analysis.globals = analysis.globals;
    target.analysis.fieldAccesses = analysis.fieldAccesses;
    target.analysis.structures = analysis.structures;
    target.analysis.offsets = analysis.offsets;
    target.analysis.signatures = analysis.signatures;
    target.analysis.identity = std::move(identity);
    target.mappedImage = std::move(mapped);
    target.rawFileSize = raw.size();
    return true;
}

ImVec4 StateColor(VersionMatchState state)
{
    switch (state)
    {
    case VersionMatchState::Exact:
    case VersionMatchState::Accepted: return ImVec4(0.20f, 0.82f, 0.48f, 1.0f);
    case VersionMatchState::StrongCandidate: return ImVec4(0.18f, 0.65f, 0.96f, 1.0f);
    case VersionMatchState::Candidate: return ImVec4(0.94f, 0.72f, 0.30f, 1.0f);
    case VersionMatchState::Ambiguous: return ImVec4(1.0f, 0.48f, 0.24f, 1.0f);
    case VersionMatchState::Rejected: return ImVec4(0.94f, 0.28f, 0.28f, 1.0f);
    default: return ImVec4(0.55f, 0.59f, 0.64f, 1.0f);
    }
}

const VersionFunctionCandidate* SelectedCandidate(const VersionFunctionMatch& match, int index)
{
    return index >= 0 && static_cast<size_t>(index) < match.candidates.size()
        ? &match.candidates[static_cast<size_t>(index)] : nullptr;
}

} // namespace

void VersionIntelligencePanel::SelectOldTarget()
{
    std::vector<wchar_t> fileName(32768, L'\0');
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.lpstrFilter = L"OpenReverse project or PE binary (*.orev;*.sys;*.exe;*.dll)\0"
                         L"*.orev;*.sys;*.exe;*.dll\0All Files (*.*)\0*.*\0";
    dialog.lpstrFile = fileName.data();
    dialog.nMaxFile = static_cast<DWORD>(fileName.size());
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER;
    dialog.lpstrTitle = L"Select the old OpenReverse project or PE binary";
    if (GetOpenFileNameW(&dialog))
    {
        oldPath_ = helpers::WideToUtf8(fileName.data());
        status_.clear();
    }
}

void VersionIntelligencePanel::StartComparison(Application& app)
{
    if (oldPath_.empty())
    {
        status_ = "Select an old .orev project or PE binary first.";
        return;
    }
    if (app.targetKind == AnalysisTargetKind::LiveProcess || app.offlineImageBuffer.empty())
    {
        status_ = "Open the new binary or dump as an offline target before comparing versions.";
        return;
    }
    const ModuleAnalysisState* analysis = app.analysisDatabase.FindModuleContaining(app.currentAddress);
    if (!analysis && !app.analysisDatabase.GetModules().empty())
        analysis = &app.analysisDatabase.GetModules().begin()->second;
    if (!analysis)
    {
        status_ = "Wait for the new target analysis to complete.";
        return;
    }
    if (jobId_ != 0) app.analysisScheduler.Cancel(jobId_);
    VersionAnalysisTarget newTarget = CurrentTarget(app, *analysis);
    const std::string oldPath = oldPath_;
    const uint64_t generation = app.targetGeneration;
    Application* application = &app;
    status_ = "Comparison queued.";
    jobId_ = app.analysisScheduler.Submit("Version Intelligence",
        [this, application, generation, oldPath, newTarget = std::move(newTarget)](
            const CancellationToken& cancellation,
            const AnalysisScheduler::ProgressCallback& progress) mutable {
            ComparisonJobResult result;
            std::string error;
            if (LoadOldPeTarget(oldPath, result.oldTarget, error, cancellation, progress))
            {
                VersionIntelligenceEngine engine;
                result.comparison = engine.Compare(result.oldTarget, newTarget, &cancellation,
                    [&](float value) { if (progress) progress(0.55f + value * 0.45f); });
            }
            else
                result.comparison.error = std::move(error);
            return [this, application, generation, result = std::move(result)]() mutable {
                jobId_ = 0;
                if (application->targetGeneration != generation) return;
                if (!result.comparison.error.empty())
                {
                    status_ = result.comparison.error;
                    return;
                }
                if (result.comparison.cancelled)
                {
                    status_ = "Comparison cancelled.";
                    return;
                }
                oldAnalysis_ = std::move(result.oldTarget);
                application->analysisSession.SetVersionComparison(std::move(result.comparison));
                selectedFunction_ = -1;
                selectedMigration_ = -1;
                status_ = "Comparison completed. Review decisions, then save the current .orev project.";
            };
        });
}

void VersionIntelligencePanel::RenderSummary(const VersionComparison& comparison) const
{
    size_t exact = 0;
    size_t strong = 0;
    size_t ambiguous = 0;
    size_t removed = 0;
    for (const auto& function : comparison.functions)
    {
        switch (EffectiveState(function.suggestedState, function.decision))
        {
        case VersionMatchState::Exact: ++exact; break;
        case VersionMatchState::StrongCandidate:
        case VersionMatchState::Accepted: ++strong; break;
        case VersionMatchState::Ambiguous: ++ambiguous; break;
        case VersionMatchState::Removed:
        case VersionMatchState::Unmatched: ++removed; break;
        default: break;
        }
    }
    ImGui::TextColored(StateColor(VersionMatchState::Exact), "Exact %zu", exact);
    ImGui::SameLine();
    ImGui::TextColored(StateColor(VersionMatchState::StrongCandidate), "Strong %zu", strong);
    ImGui::SameLine();
    ImGui::TextColored(StateColor(VersionMatchState::Ambiguous), "Ambiguous %zu", ambiguous);
    ImGui::SameLine();
    ImGui::TextDisabled("Removed %zu | New %zu | scored %zu / indexed %zu", removed,
        comparison.newFunctionRvas.size(), comparison.scoredCandidatePairs,
        comparison.indexedCandidatePairs);
}

void VersionIntelligencePanel::ApplyDecision(Application& app, const std::string& stableId,
                                             VersionDecision decision, uint64_t selectedNewRva)
{
    if (app.analysisSession.SetVersionDecision(stableId, decision, selectedNewRva))
        status_ = decision == VersionDecision::None ? "Decision reset; save the project to persist it." :
            std::string(VersionDecisionName(decision)) + "; save the project to persist it.";
}

void VersionIntelligencePanel::RenderFunctions(Application& app,
                                               const VersionComparison& comparison)
{
    if (ImGui::BeginTable("VersionFunctions", 6, ImGuiTableFlags_Borders |
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
        ImVec2(0.0f, 280.0f)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Old RVA", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Old name");
        ImGui::TableSetupColumn("New RVA", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Evidence", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Heuristic score", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableHeadersRow();
        for (size_t index = 0; index < comparison.functions.size(); ++index)
        {
            const auto& match = comparison.functions[index];
            const auto* candidate = match.candidates.empty() ? nullptr : &match.candidates.front();
            const auto state = EffectiveState(match.suggestedState, match.decision);
            ImGui::PushID(static_cast<int>(index));
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            const std::string oldRva = helpers::FormatAddress(match.oldRva, false);
            if (ImGui::Selectable(oldRva.c_str(), selectedFunction_ == static_cast<int>(index),
                                  ImGuiSelectableFlags_SpanAllColumns))
            {
                selectedFunction_ = static_cast<int>(index);
                selectedCandidate_ = 0;
            }
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(match.oldName.c_str());
            ImGui::TableSetColumnIndex(2);
            candidate ? ImGui::Text("0x%llX", static_cast<unsigned long long>(candidate->newRva))
                      : ImGui::TextDisabled("-");
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(StateColor(state), "%s", VersionMatchStateName(state));
            ImGui::TableSetColumnIndex(4); ImGui::Text("%zu", candidate ? candidate->evidence.size() : 0);
            ImGui::TableSetColumnIndex(5);
            candidate ? ImGui::Text("%.3f", candidate->similarityScore) : ImGui::TextDisabled("-");
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (selectedFunction_ < 0 || static_cast<size_t>(selectedFunction_) >= comparison.functions.size()) return;
    const auto& match = comparison.functions[static_cast<size_t>(selectedFunction_)];
    if (match.candidates.size() > 1)
    {
        ImGui::SetNextItemWidth(360.0f);
        const auto label = [](const VersionFunctionCandidate& candidate) {
            std::ostringstream stream;
            stream << candidate.newName << " @ 0x" << std::hex << std::uppercase << candidate.newRva
                   << " (score " << std::fixed << std::setprecision(3) << candidate.similarityScore << ')';
            return stream.str();
        };
        std::string preview = label(match.candidates[static_cast<size_t>(selectedCandidate_)]);
        if (ImGui::BeginCombo("Candidate", preview.c_str()))
        {
            for (size_t index = 0; index < match.candidates.size(); ++index)
            {
                const std::string item = label(match.candidates[index]);
                if (ImGui::Selectable(item.c_str(), selectedCandidate_ == static_cast<int>(index)))
                    selectedCandidate_ = static_cast<int>(index);
            }
            ImGui::EndCombo();
        }
    }
    const auto* candidate = SelectedCandidate(match, selectedCandidate_);
    if (ImGui::Button("Accept") && candidate)
        ApplyDecision(app, match.stableId, VersionDecision::Accepted, candidate->newRva);
    ImGui::SameLine();
    if (ImGui::Button("Reject")) ApplyDecision(app, match.stableId, VersionDecision::Rejected);
    ImGui::SameLine();
    if (ImGui::Button("Reset decision")) ApplyDecision(app, match.stableId, VersionDecision::None);
    ImGui::SameLine();
    if (ImGui::Button("Inspect old"))
        status_ = oldAnalysis_.analysis.functions.empty() ?
            "Run the comparison again to load old-target instruction details." : "Old details shown below.";
    ImGui::SameLine();
    if (candidate && ImGui::Button("Inspect new"))
        app.NavigateToAddress(comparison.newTarget.imageBase + candidate->newRva);
    if (!candidate) return;
    ImGui::Separator();
    ImGui::Text("Changes: instructions %+lld | blocks %+lld | edges %+lld | calls %+lld",
        static_cast<long long>(candidate->changes.instructionDelta),
        static_cast<long long>(candidate->changes.basicBlockDelta),
        static_cast<long long>(candidate->changes.edgeDelta),
        static_cast<long long>(candidate->changes.callDelta));
    if (ImGui::BeginTable("FunctionEvidence", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg,
                          ImVec2(0.0f, 160.0f)))
    {
        ImGui::TableSetupColumn("Signal"); ImGui::TableSetupColumn("Old");
        ImGui::TableSetupColumn("New"); ImGui::TableSetupColumn("Score");
        ImGui::TableSetupColumn("Detail"); ImGui::TableHeadersRow();
        for (const auto& evidence : candidate->evidence)
        {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(VersionEvidenceKindName(evidence.kind));
            ImGui::TableSetColumnIndex(1); ImGui::Text("%u", evidence.oldCount);
            ImGui::TableSetColumnIndex(2); ImGui::Text("%u", evidence.newCount);
            ImGui::TableSetColumnIndex(3); ImGui::Text("%.3f", evidence.score);
            ImGui::TableSetColumnIndex(4); ImGui::TextWrapped("%s", evidence.detail.c_str());
        }
        ImGui::EndTable();
    }
    const FunctionInfo* oldFunction = nullptr;
    if (!oldAnalysis_.analysis.functions.empty())
    {
        const uint64_t oldAddress = oldAnalysis_.analysis.module.baseAddress + match.oldRva;
        const auto found = std::find_if(oldAnalysis_.analysis.functions.begin(), oldAnalysis_.analysis.functions.end(),
            [&](const FunctionInfo& function) { return function.startAddress == oldAddress; });
        if (found != oldAnalysis_.analysis.functions.end()) oldFunction = &*found;
    }
    if (oldFunction && ImGui::CollapsingHeader("Old decoded CFG evidence"))
    {
        const std::string summary = functions::GenerateAssemblySummary(*oldFunction,
            oldAnalysis_.analysis.is64Bit);
        ImGui::BeginChild("OldFunctionEvidence", ImVec2(0.0f, 180.0f), true,
                          ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::TextUnformatted(summary.c_str());
        ImGui::EndChild();
    }
}

void VersionIntelligencePanel::RenderMigrations(Application& app,
                                                const VersionComparison& comparison,
                                                VersionMigrationKind kind)
{
    std::vector<size_t> rows;
    for (size_t index = 0; index < comparison.migrations.size(); ++index)
        if (comparison.migrations[index].kind == kind) rows.push_back(index);
    if (rows.empty())
    {
        workspace_ui::EmptyState("No migration evidence of this type was produced.");
        return;
    }
    if (ImGui::BeginTable("VersionMigrations", 6, ImGuiTableFlags_Borders |
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
        ImVec2(0.0f, 300.0f)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Identifier"); ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Old", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("New", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Evidence", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableHeadersRow();
        for (size_t row : rows)
        {
            const auto& migration = comparison.migrations[row];
            const auto state = EffectiveState(migration.suggestedState, migration.decision);
            ImGui::PushID(static_cast<int>(row));
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(migration.stableId.c_str(), selectedMigration_ == static_cast<int>(row),
                                  ImGuiSelectableFlags_SpanAllColumns))
                selectedMigration_ = static_cast<int>(row);
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(VersionMigrationKindName(migration.kind));
            ImGui::TableSetColumnIndex(2);
            migration.offsetKind == OffsetKind::StructureField
                ? ImGui::Text("%+lld", static_cast<long long>(migration.oldValue))
                : ImGui::Text("0x%llX", static_cast<unsigned long long>(migration.oldRva));
            ImGui::TableSetColumnIndex(3);
            migration.offsetKind == OffsetKind::StructureField
                ? ImGui::Text("%+lld", static_cast<long long>(migration.newValue))
                : migration.newRva != 0 ? ImGui::Text("0x%llX", static_cast<unsigned long long>(migration.newRva))
                                        : ImGui::TextDisabled("-");
            ImGui::TableSetColumnIndex(4); ImGui::TextColored(StateColor(state), "%s", VersionMatchStateName(state));
            ImGui::TableSetColumnIndex(5); ImGui::Text("%zu", migration.evidence.size());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (selectedMigration_ < 0 || static_cast<size_t>(selectedMigration_) >= comparison.migrations.size() ||
        comparison.migrations[static_cast<size_t>(selectedMigration_)].kind != kind)
        return;
    const auto& migration = comparison.migrations[static_cast<size_t>(selectedMigration_)];
    const bool actionable = migration.suggestedState == VersionMatchState::Exact ||
        migration.suggestedState == VersionMatchState::StrongCandidate ||
        migration.suggestedState == VersionMatchState::Candidate;
    if (!actionable) ImGui::BeginDisabled();
    if (ImGui::Button("Accept migration"))
        ApplyDecision(app, migration.stableId, VersionDecision::Accepted);
    if (!actionable) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Reject migration")) ApplyDecision(app, migration.stableId, VersionDecision::Rejected);
    ImGui::SameLine();
    if (ImGui::Button("Reset migration")) ApplyDecision(app, migration.stableId, VersionDecision::None);
    ImGui::SameLine();
    if (migration.newSupportRva != 0 && ImGui::Button("Inspect new evidence"))
        app.NavigateToAddress(comparison.newTarget.imageBase + migration.newSupportRva);
    for (const auto& evidence : migration.evidence)
        ImGui::BulletText("%s: %s (score %.3f)", VersionEvidenceKindName(evidence.kind),
                          evidence.detail.c_str(), evidence.score);
}

void VersionIntelligencePanel::Render(Application& app, bool* open)
{
    if (!ImGui::Begin("Version Intelligence", open, ImGuiWindowFlags_None))
    {
        ImGui::End();
        return;
    }
    workspace_ui::PanelHeader("VERSION INTELLIGENCE");
    ImGui::TextDisabled("Old target");
    ImGui::SameLine();
    ImGui::TextUnformatted(oldPath_.empty() ? "Not selected" : oldPath_.c_str());
    ImGui::SameLine();
    if (ImGui::Button("Select old...")) SelectOldTarget();
    ImGui::TextDisabled("New target");
    ImGui::SameLine();
    ImGui::TextUnformatted(app.loadedFilePath.empty() ? "Open an offline target" : app.loadedFilePath.c_str());

    const AnalysisJobSnapshot job = jobId_ != 0 ? app.analysisScheduler.GetJob(jobId_) : AnalysisJobSnapshot{};
    const bool running = job.state == AnalysisJobState::Queued || job.state == AnalysisJobState::Running;
    if (running) ImGui::BeginDisabled();
    if (ImGui::Button("Compare Versions")) StartComparison(app);
    if (running) ImGui::EndDisabled();
    if (running)
    {
        ImGui::SameLine();
        ImGui::ProgressBar(job.progress, ImVec2(220.0f, 0.0f));
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) app.analysisScheduler.Cancel(jobId_);
    }
    else if (jobId_ != 0 && job.state == AnalysisJobState::Failed)
    {
        status_ = job.error.empty() ? "Version comparison failed." : job.error;
        jobId_ = 0;
    }
    else if (jobId_ != 0 && job.state == AnalysisJobState::Cancelled)
    {
        status_ = "Comparison cancelled.";
        jobId_ = 0;
    }
    if (!status_.empty()) ImGui::TextWrapped("%s", status_.c_str());
    ImGui::Separator();

    const VersionComparison* comparison = app.analysisSession.VersionIntelligence();
    if (!comparison)
    {
        workspace_ui::EmptyState("Select an old project or binary and compare it with the current offline target.");
        ImGui::End();
        return;
    }
    ImGui::Text("%s  ->  %s", comparison->oldTarget.name.c_str(), comparison->newTarget.name.c_str());
    RenderSummary(*comparison);
    if (ImGui::BeginTabBar("VersionIntelligenceTabs"))
    {
        if (ImGui::BeginTabItem("Functions"))
        {
            RenderFunctions(app, *comparison);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Globals"))
        {
            RenderMigrations(app, *comparison, VersionMigrationKind::Global);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Offsets"))
        {
            RenderMigrations(app, *comparison, VersionMigrationKind::Offset);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Structures"))
        {
            RenderMigrations(app, *comparison, VersionMigrationKind::StructureField);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Signatures"))
        {
            RenderMigrations(app, *comparison, VersionMigrationKind::Signature);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

}} // namespace openreverse::panels
