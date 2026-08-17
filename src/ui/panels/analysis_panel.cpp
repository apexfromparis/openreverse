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
#include <cmath>
#include <deque>
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
    activeFunction_ = FunctionInfo{};
    activeAssemblySummary_.clear();
    hasAnalyzed_ = false;
    analysisJobId_ = 0;
    xrefTargetAddress_ = 0;
    lastXrefSelection_ = 0;
    cfgGraphNodes_.clear();
    cfgGraphFunction_ = 0;
    cfgGraphBlockCount_ = 0;
    cfgGraphZoom_ = 1.0f;
}

void AnalysisPanel::AnalyzeCurrentModule(Application& app)
{
    activeFunction_ = FunctionInfo();
    activeAssemblySummary_.clear();
    hasAnalyzed_ = false;
    if (!app.AnalyzeCurrentModuleSynchronously()) return;
    hasAnalyzed_ = true;
    const auto* analysis = app.CurrentAnalysis();
    if (analysis && !analysis->functions.empty())
        SelectFunction(app, analysis->functions.front().startAddress);
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
    app.PublishModuleAnalysis(std::move(result));
    activeFunction_ = FunctionInfo{};
    activeAssemblySummary_.clear();
    hasAnalyzed_ = true;
    const auto* analysis = app.CurrentAnalysis();
    if (analysis && !analysis->functions.empty())
        SelectFunction(app, analysis->functions.front().startAddress);
}

void AnalysisPanel::SelectFunction(Application& app, uint64_t funcAddress)
{
    if (!app.isAttached) return;
    const ModuleAnalysisState* analysis = app.CurrentAnalysis();
    const FunctionInfo* canonical = analysis
        ? app.analysisDatabase.FindFunction(analysis->module.baseAddress, funcAddress) : nullptr;
    if (canonical)
        activeFunction_ = *canonical;
    else
    {
        auto bytes = app.memoryReader.ReadBytes(app.processHandle, funcAddress, 65536);
        if (bytes.empty()) bytes = app.memoryReader.ReadBytes(app.processHandle, funcAddress, 8192);
        if (bytes.empty()) return;
        activeFunction_ = app.functionAnalyzer.AnalyzeFunction(bytes.data(), bytes.size(),
            funcAddress, funcAddress, app.disassembler, app.is64Bit, bytes.size());
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

    activeFunction_.xrefCount = analysis
        ? static_cast<int>(app.analysisDatabase.FindXRefsTo(
            analysis->module.baseAddress, funcAddress).size()) : 0;
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
    const ModuleAnalysisState* analysis = app.CurrentAnalysis();
    const size_t functionCount = analysis ? analysis->functions.size() : 0;
    const size_t xrefCount = analysis ? analysis->xrefs.size() : 0;
    ImGui::TextColored(ImVec4(0.00f, 0.90f, 1.00f, 1.0f), "Functions: %zu", functionCount);
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.00f, 0.90f, 0.46f, 1.0f), "XREFs: %zu", xrefCount);
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
    const ModuleAnalysisState* analysis = app.CurrentAnalysis();
    ImGui::SetNextItemWidth(250.0f);
    ImGui::InputTextWithHint("##fnfilter", "Filter functions by name/addr...", filterText_, sizeof(filterText_));
    ImGui::SameLine();
    if (ImGui::Button("Refresh Analysis") && app.processHandle)
        StartAnalyzeCurrentModule(app);

    if (!analysis || analysis->functions.empty())
    {
        ImGui::Spacing();
        ImGui::TextDisabled("No functions discovered yet. Click 'Analyze Active Module' above.");
        return;
    }

    if (ImGui::BeginTable("FunctionsTable", 7,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable))
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

        for (const auto& fn : analysis->functions)
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

void AnalysisPanel::RebuildCFGGraphLayout()
{
    constexpr size_t kMaximumVisibleNodes = 512;
    const auto& blocks = activeFunction_.cfg.basicBlocks;
    const size_t count = std::min(blocks.size(), kMaximumVisibleNodes);
    cfgGraphNodes_.clear();
    cfgGraphFunction_ = activeFunction_.startAddress;
    cfgGraphBlockCount_ = blocks.size();
    cfgGraphWidth_ = 0.0f;
    cfgGraphHeight_ = 0.0f;
    if (count == 0) return;

    std::map<uint64_t, size_t> indexByAddress;
    for (size_t index = 0; index < count; ++index)
        indexByAddress[blocks[index].startAddress] = index;
    std::vector<int> layers(count, -1);
    std::deque<size_t> pending;
    const auto entry = indexByAddress.find(activeFunction_.cfg.entryAddress);
    if (entry != indexByAddress.end())
    {
        layers[entry->second] = 0;
        pending.push_back(entry->second);
    }
    else
    {
        layers[0] = 0;
        pending.push_back(0);
    }
    while (!pending.empty())
    {
        const size_t index = pending.front();
        pending.pop_front();
        for (uint64_t successor : blocks[index].successors)
        {
            const auto found = indexByAddress.find(successor);
            if (found == indexByAddress.end() || layers[found->second] >= 0) continue;
            layers[found->second] = layers[index] + 1;
            pending.push_back(found->second);
        }
    }
    int maximumLayer = 0;
    for (size_t index = 0; index < count; ++index)
    {
        if (layers[index] < 0) layers[index] = ++maximumLayer;
        maximumLayer = std::max(maximumLayer, layers[index]);
    }
    std::vector<std::vector<size_t>> byLayer(static_cast<size_t>(maximumLayer) + 1);
    for (size_t index = 0; index < count; ++index)
        byLayer[static_cast<size_t>(layers[index])].push_back(index);

    constexpr float nodeWidth = 310.0f;
    constexpr float horizontalGap = 70.0f;
    constexpr float verticalGap = 90.0f;
    float y = 30.0f;
    for (const auto& layer : byLayer)
    {
        float maximumHeight = 0.0f;
        for (size_t blockIndex : layer)
        {
            const size_t shownInstructions = std::min<size_t>(blocks[blockIndex].instructions.size(), 10);
            maximumHeight = std::max(maximumHeight,
                58.0f + static_cast<float>(shownInstructions) * 17.0f +
                (blocks[blockIndex].instructions.size() > shownInstructions ? 17.0f : 0.0f));
        }
        const float layerWidth = layer.empty() ? 0.0f :
            layer.size() * nodeWidth + (layer.size() - 1) * horizontalGap;
        float x = 30.0f;
        for (size_t blockIndex : layer)
        {
            const size_t shownInstructions = std::min<size_t>(blocks[blockIndex].instructions.size(), 10);
            const float height = 58.0f + static_cast<float>(shownInstructions) * 17.0f +
                (blocks[blockIndex].instructions.size() > shownInstructions ? 17.0f : 0.0f);
            cfgGraphNodes_.push_back({blocks[blockIndex].startAddress, blockIndex,
                x, y, nodeWidth, height});
            x += nodeWidth + horizontalGap;
        }
        cfgGraphWidth_ = std::max(cfgGraphWidth_, layerWidth + 60.0f);
        y += maximumHeight + verticalGap;
    }
    cfgGraphHeight_ = y + 30.0f;
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

    if (cfgGraphFunction_ != activeFunction_.startAddress ||
        cfgGraphBlockCount_ != activeFunction_.cfg.basicBlocks.size())
        RebuildCFGGraphLayout();

    ImGui::TextDisabled("Ctrl + wheel: zoom  |  Middle drag: pan  |  Click a block: navigate");
    ImGui::SameLine();
    if (ImGui::SmallButton("Fit") && cfgGraphWidth_ > 0.0f && cfgGraphHeight_ > 0.0f)
    {
        const ImVec2 available = ImGui::GetContentRegionAvail();
        cfgGraphZoom_ = std::clamp(std::min(available.x / cfgGraphWidth_,
            std::max(1.0f, available.y - 32.0f) / cfgGraphHeight_), 0.45f, 1.0f);
    }
    ImGui::SameLine();
    ImGui::TextDisabled("%.0f%%", cfgGraphZoom_ * 100.0f);
    if (activeFunction_.cfg.basicBlocks.size() > cfgGraphNodes_.size())
    {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.25f, 1.0f),
                           "Showing first %zu of %zu blocks (rendering limit)",
                           cfgGraphNodes_.size(), activeFunction_.cfg.basicBlocks.size());
    }

    ImGui::BeginChild("CFGGraphCanvas", ImVec2(0, 0), true,
                      ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_NoMove);
    if (ImGui::IsWindowHovered() && ImGui::GetIO().KeyCtrl && ImGui::GetIO().MouseWheel != 0.0f)
        cfgGraphZoom_ = std::clamp(cfgGraphZoom_ + ImGui::GetIO().MouseWheel * 0.10f, 0.45f, 1.75f);
    if (ImGui::IsWindowHovered() && ImGui::IsMouseDragging(ImGuiMouseButton_Middle, 0.0f))
    {
        const ImVec2 delta = ImGui::GetIO().MouseDelta;
        ImGui::SetScrollX(std::max(0.0f, ImGui::GetScrollX() - delta.x));
        ImGui::SetScrollY(std::max(0.0f, ImGui::GetScrollY() - delta.y));
    }

    const ImVec2 canvasOrigin = ImGui::GetCursorScreenPos();
    const ImVec2 canvasSize(std::max(ImGui::GetContentRegionAvail().x, cfgGraphWidth_ * cfgGraphZoom_),
                            std::max(ImGui::GetContentRegionAvail().y, cfgGraphHeight_ * cfgGraphZoom_));
    ImGui::Dummy(canvasSize);
    ImDrawList* draw = ImGui::GetWindowDrawList();
    std::map<uint64_t, const CFGGraphNode*> nodeByAddress;
    for (const auto& node : cfgGraphNodes_) nodeByAddress[node.address] = &node;
    const auto graphPoint = [&](float x, float y) {
        return ImVec2(canvasOrigin.x + x * cfgGraphZoom_, canvasOrigin.y + y * cfgGraphZoom_);
    };

    // Draw connections first so block cards stay legible above the graph.
    for (const auto& edge : activeFunction_.cfg.edges)
    {
        const auto sourceIt = nodeByAddress.find(edge.source);
        const auto targetIt = nodeByAddress.find(edge.target);
        if (sourceIt == nodeByAddress.end() || targetIt == nodeByAddress.end()) continue;
        const CFGGraphNode& source = *sourceIt->second;
        const CFGGraphNode& target = *targetIt->second;
        const ImVec2 start = graphPoint(source.x + source.width * 0.5f, source.y + source.height);
        const ImVec2 finish = graphPoint(target.x + target.width * 0.5f, target.y);
        const float bend = std::max(35.0f, std::abs(finish.y - start.y) * 0.45f);
        const float direction = finish.y >= start.y ? 1.0f : -1.0f;
        const ImVec2 control1(start.x, start.y + bend * direction);
        const ImVec2 control2(finish.x, finish.y - bend * direction);
        const ImU32 color = ImGui::ColorConvertFloat4ToU32(edgeColor(edge.type));
        draw->AddBezierCubic(start, control1, control2, finish, color,
                             std::max(1.25f, 2.0f * cfgGraphZoom_));
        const ImVec2 tangent(finish.x - control2.x, finish.y - control2.y);
        const float length = std::sqrt(tangent.x * tangent.x + tangent.y * tangent.y);
        if (length > 0.01f)
        {
            const ImVec2 unit(tangent.x / length, tangent.y / length);
            const ImVec2 normal(-unit.y, unit.x);
            const float arrow = 8.0f * cfgGraphZoom_;
            draw->AddTriangleFilled(finish,
                ImVec2(finish.x - unit.x * arrow + normal.x * arrow * 0.55f,
                       finish.y - unit.y * arrow + normal.y * arrow * 0.55f),
                ImVec2(finish.x - unit.x * arrow - normal.x * arrow * 0.55f,
                       finish.y - unit.y * arrow - normal.y * arrow * 0.55f), color);
        }
    }

    const auto textColor = IM_COL32(220, 226, 234, 255);
    const auto mutedColor = IM_COL32(125, 137, 151, 255);
    for (const auto& node : cfgGraphNodes_)
    {
        const auto& block = activeFunction_.cfg.basicBlocks[node.blockIndex];
        const ImVec2 topLeft = graphPoint(node.x, node.y);
        const ImVec2 bottomRight = graphPoint(node.x + node.width, node.y + node.height);
        const bool entryBlock = block.startAddress == activeFunction_.cfg.entryAddress;
        const ImU32 border = entryBlock ? IM_COL32(35, 213, 140, 255) :
                             block.isTerminal ? IM_COL32(225, 85, 92, 255) : IM_COL32(22, 159, 205, 255);
        draw->AddRectFilled(topLeft, bottomRight, IM_COL32(15, 20, 27, 250), 5.0f);
        draw->AddRect(topLeft, bottomRight, border, 5.0f, 0, std::max(1.0f, 1.5f * cfgGraphZoom_));
        const float headerHeight = 32.0f * cfgGraphZoom_;
        draw->AddRectFilled(topLeft, ImVec2(bottomRight.x, topLeft.y + headerHeight),
                            IM_COL32(23, 32, 43, 255), 5.0f, ImDrawFlags_RoundCornersTop);
        char title[96];
        snprintf(title, sizeof(title), "Block %zu  %s", node.blockIndex,
                 helpers::FormatAddress(block.startAddress, app.is64Bit).c_str());
        draw->AddText(ImVec2(topLeft.x + 10.0f * cfgGraphZoom_, topLeft.y + 8.0f * cfgGraphZoom_),
                      textColor, title);
        char badge[96];
        snprintf(badge, sizeof(badge), "%s%s%zu pred / %zu succ",
                 entryBlock ? "ENTRY  " : "", block.isTerminal ? "EXIT  " : "",
                 block.predecessors.size(), block.successors.size());
        draw->AddText(ImVec2(topLeft.x + 10.0f * cfgGraphZoom_, topLeft.y + 37.0f * cfgGraphZoom_),
                      mutedColor, badge);

        const size_t shown = std::min<size_t>(block.instructions.size(), 10);
        for (size_t index = 0; index < shown; ++index)
        {
            const auto& instruction = block.instructions[index];
            std::string line = helpers::FormatAddress(instruction.address, app.is64Bit) + "  " +
                               instruction.mnemonic;
            if (!instruction.operands.empty()) line += "  " + instruction.operands;
            const ImU32 instructionColor = instruction.isCall ? IM_COL32(40, 218, 255, 255) :
                instruction.isJump ? IM_COL32(255, 178, 68, 255) :
                instruction.isRet ? IM_COL32(255, 91, 91, 255) : textColor;
            draw->AddText(ImVec2(topLeft.x + 10.0f * cfgGraphZoom_,
                                 topLeft.y + (56.0f + static_cast<float>(index) * 17.0f) * cfgGraphZoom_),
                          instructionColor, line.c_str());
        }
        if (block.instructions.size() > shown)
            draw->AddText(ImVec2(topLeft.x + 10.0f * cfgGraphZoom_,
                                 topLeft.y + (56.0f + static_cast<float>(shown) * 17.0f) * cfgGraphZoom_),
                          mutedColor, "...");

        ImGui::SetCursorScreenPos(topLeft);
        ImGui::PushID(static_cast<int>(node.blockIndex));
        if (ImGui::InvisibleButton("##CFGBlock", ImVec2(node.width * cfgGraphZoom_, node.height * cfgGraphZoom_)))
            app.NavigateToAddress(block.startAddress);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Navigate to %s", helpers::FormatAddress(block.startAddress, app.is64Bit).c_str());
        ImGui::PopID();
    }
    ImGui::SetCursorScreenPos(ImVec2(canvasOrigin.x, canvasOrigin.y + canvasSize.y));
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
