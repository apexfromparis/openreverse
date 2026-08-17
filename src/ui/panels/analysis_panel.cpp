#include "analysis_panel.h"
#include "app/application.h"
#include "core/module_manager.h"
#include "core/string_scanner.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include "utils/logger.h"

#include <imgui.h>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <map>

namespace openreverse { namespace panels {

namespace {

const char* FunctionSourceName(FunctionSource source)
{
    switch (source)
    {
    case FunctionSource::RuntimeFunction: return "Runtime";
    case FunctionSource::Symbol: return "Symbol";
    case FunctionSource::Export: return "Export";
    case FunctionSource::EntryPoint: return "Entry";
    case FunctionSource::DirectCall: return "Call";
    case FunctionSource::RecursiveTraversal: return "Traversal";
    case FunctionSource::Heuristic: return "Heuristic";
    case FunctionSource::UserDefined: return "User";
    default: return "Unknown";
    }
}

} // namespace

void AnalysisPanel::ResetAnalysis()
{
    functions_.clear();
    activeFunction_ = FunctionInfo{};
    activeAssemblySummary_.clear();
    hasAnalyzed_ = false;
    analysisJobId_ = 0;
    xrefTargetAddress_ = 0;
    lastXrefSelection_ = 0;
}

void AnalysisPanel::AnalyzeCurrentModule(Application& app)
{
    if (!app.isAttached)
        return;
    if (!app.processHandle)
    {
        Logger::Get().Log(LogLevel::Info, "Offline PE analysis is already available from the loaded image.");
        return;
    }

    functions_.clear();
    activeFunction_ = FunctionInfo();
    activeAssemblySummary_.clear();
    app.xrefScanner.Clear();
    hasAnalyzed_ = false;

    auto* mod = app.moduleManager.FindModuleByAddress(app.currentAddress);
    if (!mod && !app.moduleManager.GetModules().empty())
        mod = const_cast<ModuleInfo*>(&app.moduleManager.GetModules()[0]);

    if (!mod)
    {
        Logger::Get().Log(LogLevel::Warning, "No module found to analyze.");
        return;
    }
    ModuleAnalyzer analyzer;
    ApplyModuleAnalysis(app, analyzer.AnalyzeLive(app.processHandle, *mod, app.is64Bit));
}

void AnalysisPanel::StartAnalyzeCurrentModule(Application& app)
{
    if (!app.isAttached || !app.processHandle)
        return;
    auto* module = app.moduleManager.FindModuleByAddress(app.currentAddress);
    if (!module && !app.moduleManager.GetModules().empty())
        module = const_cast<ModuleInfo*>(&app.moduleManager.GetModules()[0]);
    if (!module)
        return;

    if (analysisJobId_ != 0)
        app.analysisScheduler.Cancel(analysisJobId_);

    HANDLE duplicated = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), app.processHandle, GetCurrentProcess(), &duplicated,
                         PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, 0))
    {
        Logger::Get().Log(LogLevel::Error, "Could not duplicate the process handle for background analysis.");
        return;
    }
    auto ownedHandle = std::shared_ptr<void>(duplicated, [](void* handle) {
        if (handle) CloseHandle(static_cast<HANDLE>(handle));
    });
    const ModuleInfo moduleCopy = *module;
    const bool is64Bit = app.is64Bit;
    Application* application = &app;
    hasAnalyzed_ = false;

    analysisJobId_ = app.analysisScheduler.Submit("Live module analysis",
        [this, application, ownedHandle, moduleCopy, is64Bit](
            const CancellationToken& cancellation,
            const AnalysisScheduler::ProgressCallback& progress) {
            ModuleAnalyzer analyzer;
            auto result = analyzer.AnalyzeLive(static_cast<HANDLE>(ownedHandle.get()), moduleCopy,
                                               is64Bit, {}, &cancellation, progress);
            return [this, application, result = std::move(result)]() mutable {
                analysisJobId_ = 0;
                ApplyModuleAnalysis(*application, std::move(result));
            };
        });
}

void AnalysisPanel::ApplyModuleAnalysis(Application& app, ModuleAnalysisResult result)
{
    if (!result.success)
    {
        if (!result.cancelled)
            Logger::Get().Log(LogLevel::Error, "Module analysis failed: %s", result.error.c_str());
        return;
    }
    app.analysisSession.ApplyPersistedAnalysis(result);
    app.analysisDatabase.ReplaceModuleAnalysis(result.module, app.is64Bit, result.pe,
                                               result.functions, result.xrefs, result.strings,
                                               result.globals, result.fieldAccesses, result.structures,
                                               result.offsets, result.signatures, result.identity,
                                               result.symbols, result.symbolTypes, result.symbolIdentity);
    functions_ = std::move(result.functions);
    app.xrefScanner.ReplaceEntries(std::move(result.xrefs));
    app.stringResults = std::move(result.strings);
    activeFunction_ = FunctionInfo{};
    activeAssemblySummary_.clear();
    hasAnalyzed_ = true;
    Logger::Get().Log(LogLevel::Info,
        "Module analysis: %zu functions, %zu Xrefs, %zu strings, %zu globals, %zu structures, "
        "%lld ms (PE %lld, code %lld, strings %lld)",
        functions_.size(), app.xrefScanner.GetTotalXRefsCount(), app.stringResults.size(),
        result.globals.size(), result.structures.size(),
        static_cast<long long>(result.totalDuration.count()),
        static_cast<long long>(result.peDuration.count()),
        static_cast<long long>(result.codeDuration.count()),
        static_cast<long long>(result.stringDuration.count()));
    if (result.codeBudgetReached || result.instructionBudgetReached || result.functionLimitReached ||
        result.stringBudgetReached || result.timeBudgetReached)
        Logger::Get().Log(LogLevel::Warning, "Module analysis stopped at a configured limit");
    if (!functions_.empty())
        SelectFunction(app, functions_[0].startAddress);
    app.RestoreProjectUiAfterAnalysis();
    app.NotifyExtensionsSessionChanged();
}

void AnalysisPanel::SetPEAnalysisResult(const std::vector<Instruction>& insns, const std::vector<PESectionInfo>& sections, const std::vector<PEImportEntry>& imports, const std::vector<PEInfo::PEExportEntry>& exports, bool is64Bit, const std::vector<FunctionInfo>& discoveredFuncs)
{
    functions_.clear();
    activeFunction_ = FunctionInfo();
    activeAssemblySummary_.clear();
    hasAnalyzed_ = true;

    if (!discoveredFuncs.empty())
    {
        functions_ = discoveredFuncs;
    }
    else if (!insns.empty())
    {
        FunctionInfo fn;
        fn.name = "entry_point";
        fn.startAddress = insns[0].address;
        fn.source = FunctionSource::EntryPoint;
        fn.analyzedEndAddress = insns.back().address + insns.back().size;
        fn.analyzedSize = static_cast<size_t>(fn.analyzedEndAddress - fn.startAddress);
        functions_.push_back(fn);
    }
    if (!functions_.empty())
        activeFunction_ = functions_[0];
}

void AnalysisPanel::SelectFunction(Application& app, uint64_t funcAddress)
{
    if (!app.isAttached) return;

    size_t readSize = 65536; // 64 KB function scan window
    auto bytes = app.memoryReader.ReadBytes(app.processHandle, funcAddress, readSize);
    if (bytes.empty())
    {
        bytes = app.memoryReader.ReadBytes(app.processHandle, funcAddress, 8192);
        if (bytes.empty()) return;
    }

    activeFunction_ = app.functionAnalyzer.AnalyzeFunction(bytes.data(), bytes.size(), funcAddress, funcAddress, app.disassembler, app.is64Bit, 65536);
    for (const auto& f : functions_)
    {
        if (f.startAddress == funcAddress && !f.name.empty())
        {
            activeFunction_.name = f.name;
            activeFunction_.source = f.source;
            activeFunction_.boundaryKnown = f.boundaryKnown;
            activeFunction_.endAddress = f.endAddress;
            activeFunction_.size = f.size;
            break;
        }
    }
    if (const ModuleInfo* module = app.moduleManager.FindModuleByAddress(funcAddress))
    {
        if (const ProjectFunctionAnnotation* annotation =
                app.analysisSession.FindFunctionAnnotation(funcAddress - module->baseAddress))
        {
            if (!annotation->name.empty()) activeFunction_.name = annotation->name;
        }
    }

    activeAssemblySummary_ = app.functionAnalyzer.GenerateAssemblySummary(activeFunction_, app.is64Bit);
    app.NavigateToAddress(funcAddress);

    auto xrefs = app.xrefScanner.FindXRefsTo(funcAddress);
    activeFunction_.xrefCount = (int)xrefs.size();
}

void AnalysisPanel::Render(Application& app)
{
    ImGui::Begin("Analysis / Functions & CFG", nullptr, ImGuiWindowFlags_None);

    AnalysisJobSnapshot analysisJob = analysisJobId_ != 0
        ? app.analysisScheduler.GetJob(analysisJobId_) : AnalysisJobSnapshot{};
    const bool analysisWorking = analysisJob.state == AnalysisJobState::Queued ||
        analysisJob.state == AnalysisJobState::Running;
    if (analysisJobId_ != 0 && analysisJob.state == AnalysisJobState::Cancelled)
        analysisJobId_ = 0;

    UIManager::BeginToolbar();
    if (!app.processHandle || analysisWorking) ImGui::BeginDisabled();
    if (ImGui::Button("Analyze Active Module"))
    {
        StartAnalyzeCurrentModule(app);
    }
    if (!app.processHandle || analysisWorking) ImGui::EndDisabled();
    if (analysisWorking)
    {
        ImGui::SameLine();
        ImGui::ProgressBar(analysisJob.progress, ImVec2(90.0f, 0.0f));
        ImGui::SameLine();
        if (ImGui::SmallButton("Cancel##moduleanalysis")) app.analysisScheduler.Cancel(analysisJobId_);
    }
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.00f, 0.90f, 1.00f, 1.0f), "Functions: %zu", functions_.size());
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.00f, 0.90f, 0.46f, 1.0f), "XREFs: %zu", app.xrefScanner.GetTotalXRefsCount());
    ImGui::SameLine();
    if (activeFunction_.startAddress != 0)
    {
        ImGui::TextColored(ImVec4(1.00f, 0.67f, 0.25f, 1.0f), "| Selected: %s (%s)",
                           activeFunction_.name.c_str(), helpers::FormatAddress(activeFunction_.startAddress, app.is64Bit).c_str());
    }
    UIManager::EndToolbar();

    ImGui::Separator();

    if (ImGui::BeginTabBar("AnalysisTabs"))
    {
        if (ImGui::BeginTabItem("Functions"))
        {
            if (!app.isAttached)
                UIManager::EmptyState("Open a binary or attach to a process to analyze functions.");
            else
                RenderFunctionsTab(app);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("CFG Basic Blocks"))
        {
            if (!app.isAttached)
                UIManager::EmptyState("Attach to a process to use CFG graph analysis.");
            else
                RenderCFGTab(app);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Assembly Summary"))
        {
            if (!app.isAttached)
                UIManager::EmptyState("Open a binary or attach to inspect decoded control-flow evidence.");
            else
                RenderAssemblySummaryTab(app);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("XREFs (Cross-References)"))
        {
            if (!app.isAttached)
                UIManager::EmptyState("Attach to a process to scan cross-references.");
            else
                RenderXRefsTab(app);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
}

void AnalysisPanel::RenderXRefsPanel(Application& app)
{
    ImGui::Begin("XREFS", nullptr, ImGuiWindowFlags_None);
    UIManager::PanelHeader("XREFS");
    if (!app.isAttached)
        UIManager::EmptyState("Open a binary or attach to a process to inspect cross-references.");
    else
        RenderXRefsTab(app);
    ImGui::End();
}

void AnalysisPanel::RenderFunctionsTab(Application& app)
{
    ImGui::SetNextItemWidth(250.0f);
    ImGui::InputTextWithHint("##fnfilter", "Filter functions by name/addr...", filterText_, sizeof(filterText_));
    ImGui::SameLine();
    if (ImGui::Button("Refresh Analysis") && app.processHandle)
        StartAnalyzeCurrentModule(app);

    if (functions_.empty())
    {
        ImGui::Spacing();
        ImGui::TextDisabled("No functions discovered yet. Click 'Analyze Active Module' above.");
        return;
    }

    if (ImGui::BeginTable("FunctionsTable", 7,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Function Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 75.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Blocks", ImGuiTableColumnFlags_WidthFixed, 65.0f);
        ImGui::TableSetupColumn("V(G)", ImGuiTableColumnFlags_WidthFixed, 55.0f);
        ImGui::TableSetupColumn("XREFs", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableHeadersRow();

        std::string filterLower = helpers::ToLower(filterText_);

        for (const auto& fn : functions_)
        {
            std::string addrStr = helpers::FormatAddress(fn.startAddress, app.is64Bit);
            const ModuleInfo* module = app.moduleManager.FindModuleByAddress(fn.startAddress);
            const uint64_t rva = module ? fn.startAddress - module->baseAddress : 0;
            const ProjectFunctionAnnotation* annotation = module
                ? app.analysisSession.FindFunctionAnnotation(rva) : nullptr;
            const std::string& displayName = annotation && !annotation->name.empty()
                ? annotation->name : fn.name;
            if (!filterLower.empty() &&
                helpers::ToLower(displayName).find(filterLower) == std::string::npos &&
                helpers::ToLower(addrStr).find(filterLower) == std::string::npos)
            {
                continue;
            }

            ImGui::TableNextRow();
            bool isCurrent = (fn.startAddress == activeFunction_.startAddress);
            if (isCurrent)
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                    ImGui::GetColorU32(ImVec4(0.00f, 0.32f, 0.38f, 0.40f)));

            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(addrStr.c_str(), isCurrent, ImGuiSelectableFlags_SpanAllColumns))
            {
                SelectFunction(app, fn.startAddress);
            }
            if (module && app.targetKind != AnalysisTargetKind::LiveProcess &&
                ImGui::BeginPopupContextItem())
            {
                if (ImGui::MenuItem("Edit project annotation..."))
                {
                    annotationRva_ = rva;
                    const std::string name = annotation ? annotation->name : fn.name;
                    const std::string comment = annotation ? annotation->comment : std::string{};
                    strncpy_s(annotationName_, sizeof(annotationName_), name.c_str(), _TRUNCATE);
                    strncpy_s(annotationComment_, sizeof(annotationComment_), comment.c_str(), _TRUNCATE);
                    requestAnnotationPopup_ = true;
                }
                ImGui::EndPopup();
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.40f, 0.85f, 0.95f, 1.0f), "%s", displayName.c_str());
            if (annotation && !annotation->comment.empty() && ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", annotation->comment.c_str());

            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(FunctionSourceName(fn.source));

            ImGui::TableSetColumnIndex(3);
            if (fn.boundaryKnown) ImGui::Text("%zu B", fn.size);
            else ImGui::TextDisabled("Unknown");

            ImGui::TableSetColumnIndex(4);
            ImGui::Text("%zu", fn.cfg.basicBlocks.size());

            ImGui::TableSetColumnIndex(5);
            if (fn.cfg.basicBlocks.empty())
                ImGui::TextDisabled("Unknown");
            else
            {
                ImVec4 compColor = (fn.cyclomaticComplexity >= 10) ? ImVec4(1.0f, 0.4f, 0.4f, 1.0f) :
                                   (fn.cyclomaticComplexity >= 5)  ? ImVec4(1.0f, 0.75f, 0.3f, 1.0f) :
                                                                     ImVec4(0.7f, 0.85f, 0.7f, 1.0f);
                ImGui::TextColored(compColor, "%d", fn.cyclomaticComplexity);
            }

            ImGui::TableSetColumnIndex(6);
            ImGui::TextColored(ImVec4(0.85f, 0.65f, 0.95f, 1.0f), "%d", fn.xrefCount);
        }

        ImGui::EndTable();
    }
    RenderAnnotationPopup(app);
}

void AnalysisPanel::RenderAnnotationPopup(Application& app)
{
    if (requestAnnotationPopup_)
    {
        ImGui::OpenPopup("Function project annotation");
        requestAnnotationPopup_ = false;
    }
    if (!ImGui::BeginPopupModal("Function project annotation", nullptr,
                                ImGuiWindowFlags_AlwaysAutoResize))
        return;

    ImGui::TextDisabled("RVA 0x%llX", static_cast<unsigned long long>(annotationRva_));
    ImGui::SetNextItemWidth(420.0f);
    ImGui::InputText("Name", annotationName_, sizeof(annotationName_));
    ImGui::SetNextItemWidth(420.0f);
    ImGui::InputTextMultiline("Comment", annotationComment_, sizeof(annotationComment_),
                              ImVec2(420.0f, 100.0f));
    if (ImGui::Button("Save", ImVec2(90.0f, 0.0f)))
    {
        app.analysisSession.SetFunctionAnnotation(annotationRva_, annotationName_, annotationComment_);
        const ModuleAnalysisState* analysis = app.analysisDatabase.FindModuleContaining(app.currentAddress);
        if (analysis) SelectFunction(app, analysis->module.baseAddress + annotationRva_);
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Remove", ImVec2(90.0f, 0.0f)))
    {
        app.analysisSession.RemoveFunctionAnnotation(annotationRva_);
        const ModuleAnalysisState* analysis = app.analysisDatabase.FindModuleContaining(app.currentAddress);
        if (analysis) SelectFunction(app, analysis->module.baseAddress + annotationRva_);
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(90.0f, 0.0f)))
        ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void AnalysisPanel::RenderCFGTab(Application& app)
{
    if (activeFunction_.startAddress == 0)
    {
        ImGui::Spacing();
        ImGui::TextDisabled("No function selected. Select a function from the Functions tab.");
        return;
    }

    ImGui::TextColored(ImVec4(0.00f, 0.90f, 1.00f, 1.0f), "Function: %s (%s)",
                       activeFunction_.name.c_str(), helpers::FormatAddress(activeFunction_.startAddress, app.is64Bit).c_str());
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.75f, 0.75f, 0.80f, 1.0f),
                       "| %zu Blocks | %zu Edges | %zu Instructions | V(G): %d",
                       activeFunction_.cfg.basicBlocks.size(), activeFunction_.cfg.edges.size(),
                       activeFunction_.cfg.decodedInstructionCount, activeFunction_.cyclomaticComplexity);
    ImGui::SameLine();
    const char* cfgStatus = activeFunction_.cfg.complete ? "Complete" :
        (activeFunction_.cfg.instructionBudgetReached ? "Instruction budget reached" : "Incomplete");
    ImGui::TextColored(activeFunction_.cfg.complete ? ImVec4(0.25f, 0.85f, 0.50f, 1.0f)
                                                    : ImVec4(1.0f, 0.55f, 0.25f, 1.0f),
                       "%s", cfgStatus);
    ImGui::Separator();

    const auto edgeName = [](CFGEdgeType type) {
        switch (type)
        {
        case CFGEdgeType::Fallthrough: return "Fallthrough";
        case CFGEdgeType::ConditionalTrue: return "True";
        case CFGEdgeType::ConditionalFalse: return "False";
        case CFGEdgeType::Unconditional: return "Jump";
        case CFGEdgeType::Return: return "Return";
        }
        return "Unknown";
    };
    const auto edgeColor = [](CFGEdgeType type) {
        switch (type)
        {
        case CFGEdgeType::ConditionalTrue: return ImVec4(0.95f, 0.48f, 0.25f, 1.0f);
        case CFGEdgeType::ConditionalFalse: return ImVec4(0.30f, 0.80f, 0.50f, 1.0f);
        case CFGEdgeType::Unconditional: return ImVec4(0.85f, 0.65f, 0.25f, 1.0f);
        case CFGEdgeType::Return: return ImVec4(0.90f, 0.35f, 0.40f, 1.0f);
        default: return ImVec4(0.35f, 0.70f, 0.90f, 1.0f);
        }
    };

    if (ImGui::CollapsingHeader("Typed Edge Index"))
    {
        if (ImGui::BeginTable("CFGEdges", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("Source");
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableSetupColumn("Target");
            ImGui::TableHeadersRow();
            for (const auto& edge : activeFunction_.cfg.edges)
            {
                ImGui::PushID(&edge);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                const auto source = helpers::FormatAddress(edge.source, app.is64Bit);
                if (ImGui::Selectable(source.c_str())) app.NavigateToAddress(edge.source);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(edgeColor(edge.type), "%s", edgeName(edge.type));
                ImGui::TableSetColumnIndex(2);
                if (edge.target == 0)
                    ImGui::TextDisabled("Function exit");
                else
                {
                    const auto target = helpers::FormatAddress(edge.target, app.is64Bit);
                    if (ImGui::Selectable(target.c_str())) app.NavigateToAddress(edge.target);
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::Separator();
    }

    ImGui::BeginChild("CFGBlocksScroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    for (size_t i = 0; i < activeFunction_.cfg.basicBlocks.size(); ++i)
    {
        const auto& bb = activeFunction_.cfg.basicBlocks[i];
        ImGui::PushID((int)i);

        ImGui::BeginGroup();
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.14f, 0.18f, 0.95f));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.00f, 0.55f, 0.65f, 0.80f));

        char header[128];
        snprintf(header, sizeof(header), "Basic Block %zu [0x%llX -> 0x%llX] (%zu insns)",
                 i, (unsigned long long)bb.startAddress, (unsigned long long)bb.endAddress, bb.instructions.size());

        if (ImGui::CollapsingHeader(header, ImGuiTreeNodeFlags_DefaultOpen))
        {
            bool showedBlockBadge = false;
            if (bb.startAddress == activeFunction_.cfg.entryAddress)
            {
                ImGui::TextColored(ImVec4(0.25f, 0.85f, 0.50f, 1.0f), "ENTRY");
                showedBlockBadge = true;
            }
            if (bb.isTerminal)
            {
                if (showedBlockBadge) ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.95f, 0.42f, 0.42f, 1.0f), "TERMINAL");
                showedBlockBadge = true;
            }
            if (showedBlockBadge) ImGui::SameLine();
            ImGui::TextDisabled("Predecessors: %zu | Successors: %zu",
                                bb.predecessors.size(), bb.successors.size());
            if (UIManager::GetMonoFont()) ImGui::PushFont(UIManager::GetMonoFont());

            for (const auto& ins : bb.instructions)
            {
                std::string addrStr = helpers::FormatAddress(ins.address, app.is64Bit);
                ImGui::TextColored(ImVec4(0.45f, 0.50f, 0.55f, 1.0f), "%s", addrStr.c_str());
                ImGui::SameLine(130.0f);

                ImVec4 mnemonicColor = ins.isCall ? ImVec4(0.00f, 0.90f, 1.0f, 1.0f) :
                                       ins.isJump ? ImVec4(1.0f, 0.67f, 0.25f, 1.0f) :
                                       ins.isRet  ? ImVec4(1.0f, 0.32f, 0.32f, 1.0f) :
                                                    ImVec4(0.85f, 0.87f, 0.90f, 1.0f);

                ImGui::TextColored(mnemonicColor, "%-8s", ins.mnemonic.c_str());
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.70f, 0.75f, 0.80f, 1.0f), "%s", ins.operands.c_str());
            }

            if (UIManager::GetMonoFont()) ImGui::PopFont();

            ImGui::Spacing();
            bool hasOutgoingEdge = false;
            for (const auto& edge : activeFunction_.cfg.edges)
            {
                if (edge.source != bb.startAddress) continue;
                if (hasOutgoingEdge) ImGui::SameLine();
                ImGui::PushStyleColor(ImGuiCol_Button, edgeColor(edge.type));
                char edgeButton[96];
                if (edge.target == 0)
                    snprintf(edgeButton, sizeof(edgeButton), "%s -> exit", edgeName(edge.type));
                else
                    snprintf(edgeButton, sizeof(edgeButton), "%s -> 0x%llX", edgeName(edge.type),
                             static_cast<unsigned long long>(edge.target));
                if (ImGui::Button(edgeButton) && edge.target != 0) app.NavigateToAddress(edge.target);
                ImGui::PopStyleColor();
                hasOutgoingEdge = true;
            }
        }

        ImGui::PopStyleColor(2);
        ImGui::EndGroup();
        ImGui::PopID();
        ImGui::Spacing();
    }

    ImGui::EndChild();
}

void AnalysisPanel::RenderAssemblySummaryTab(Application& app)
{
    if (activeFunction_.startAddress == 0 || activeAssemblySummary_.empty())
    {
        ImGui::Spacing();
        ImGui::TextDisabled("No decoded summary is available. Select a function from the Functions tab.");
        return;
    }

    if (ImGui::Button("Copy Summary"))
    {
        ImGui::SetClipboardText(activeAssemblySummary_.c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Ask AI to Review"))
    {
        std::string req = "Review this decoded control-flow evidence for " + activeFunction_.name +
                          ". Separate observations from inferences:\n\n```asm\n" +
                          activeAssemblySummary_ + "\n```";
        app.aiService.Send(req);
    }
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.00f, 0.90f, 0.46f, 1.0f), "Decoded CFG evidence");

    ImGui::Separator();

    if (UIManager::GetMonoFont())
        ImGui::PushFont(UIManager::GetMonoFont());

    ImGui::BeginChild("AssemblySummaryTextWindow", ImVec2(0, 0), true,
                      ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextUnformatted(activeAssemblySummary_.c_str());
    ImGui::EndChild();

    if (UIManager::GetMonoFont())
        ImGui::PopFont();
}

void AnalysisPanel::RenderXRefsTab(Application& app)
{
    if (xrefTargetAddress_ != 0)
    {
        lastXrefSelection_ = xrefTargetAddress_;
        xrefTargetAddress_ = 0;
    }
    else if (app.currentAddress != 0)
    {
        lastXrefSelection_ = app.currentAddress;
    }

    const auto incoming = app.xrefScanner.FindXRefsTo(lastXrefSelection_);
    const auto outgoing = app.xrefScanner.FindXRefsFrom(lastXrefSelection_);
    if (lastXrefSelection_ != 0)
        ImGui::TextDisabled("Selection %s", helpers::FormatAddress(lastXrefSelection_, app.is64Bit).c_str());

    if (incoming.empty() && outgoing.empty())
    {
        UIManager::EmptyState("No cross-references available for the current selection.");
        return;
    }

    if (ImGui::BeginTable("XRefsTable", 4,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Direction", ImGuiTableColumnFlags_WidthFixed, 58.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Operand", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        const auto renderRow = [&](const XRefEntry& xr, bool isIncoming) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextDisabled("%s", isIncoming ? "IN" : "OUT");
            ImGui::TableSetColumnIndex(1);
            const uint64_t navigationAddress = isIncoming ? xr.fromAddress : xr.toAddress;
            const std::string address = helpers::FormatAddress(navigationAddress, app.is64Bit);
            if (ImFont* mono = UIManager::GetMonoFont()) ImGui::PushFont(mono);
            if (ImGui::Selectable(address.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                app.NavigateToAddress(navigationAddress);
            if (UIManager::GetMonoFont()) ImGui::PopFont();
            ImGui::TableSetColumnIndex(2);
            const char* typeStr = (xr.type == XRefType::Call) ? "CALL" :
                                  (xr.type == XRefType::Jump) ? "JUMP" :
                                  (xr.type == XRefType::Address)  ? "ADDRESS" :
                                  (xr.type == XRefType::Read) ? "READ" :
                                  (xr.type == XRefType::ReadWrite) ? "R/W" :
                                  (xr.type == XRefType::Write) ? "WRITE" :
                                  (xr.type == XRefType::String) ? "STRING" :
                                  (xr.type == XRefType::Import) ? "IMPORT" :
                                  (xr.type == XRefType::Global) ? "GLOBAL" : "DATA";
            ImGui::TextColored(xr.type == XRefType::Call ? ImVec4(0.08f, 0.55f, 0.92f, 1.0f)
                                                         : ImVec4(0.72f, 0.77f, 0.81f, 1.0f), "%s", typeStr);
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(xr.instructionText.c_str());
        };

        for (const auto& xr : incoming) renderRow(xr, true);
        for (const auto& xr : outgoing) renderRow(xr, false);

        ImGui::EndTable();
    }
}

}} // namespace openreverse::panels
