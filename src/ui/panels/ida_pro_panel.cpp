// ============================================================================
// OpenReverse - UI Panel: Analysis Workspace Implementation
// ============================================================================

#include "ida_pro_panel.h"
#include "app/application.h"
#include "core/module_manager.h"
#include "core/string_scanner.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include "utils/logger.h"
#include "TextEditor.h"

#include <imgui.h>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <map>

namespace openreverse { namespace panels {

IDAProPanel::~IDAProPanel()
{
    if (textEditorPtr_) {
        delete textEditorPtr_;
        textEditorPtr_ = nullptr;
    }
}

void IDAProPanel::ResetAnalysis()
{
    functions_.clear();
    activeFunction_ = FunctionInfo{};
    activePseudocode_.clear();
    currentXrefs_.clear();
    hasAnalyzed_ = false;
    analysisJobId_ = 0;
    xrefTargetAddress_ = 0;
    xrefAddressInput_[0] = '0';
    xrefAddressInput_[1] = '\0';
    devAiResponse_ = "Ask the configured AI provider for help drafting analysis heuristics.";
    scriptLog_ = "[*] Editor preview initialized. Script execution and publishing are unavailable.\n";
}

void IDAProPanel::AnalyzeCurrentModule(Application& app)
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
    activePseudocode_.clear();
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

void IDAProPanel::StartAnalyzeCurrentModule(Application& app)
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

void IDAProPanel::ApplyModuleAnalysis(Application& app, ModuleAnalysisResult result)
{
    if (!result.success)
    {
        if (!result.cancelled)
            Logger::Get().Log(LogLevel::Error, "Live module analysis failed: %s", result.error.c_str());
        return;
    }
    app.analysisDatabase.ReplaceModuleAnalysis(result.module, app.is64Bit, result.pe,
                                               result.functions, result.xrefs, result.strings,
                                               result.globals, result.fieldAccesses, result.structures);
    functions_ = std::move(result.functions);
    app.xrefScanner.ReplaceEntries(std::move(result.xrefs));
    app.stringResults = std::move(result.strings);
    activeFunction_ = FunctionInfo{};
    activePseudocode_.clear();
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
}

void IDAProPanel::SetPEAnalysisResult(const std::vector<Instruction>& insns, const std::vector<PESectionInfo>& sections, const std::vector<PEImportEntry>& imports, const std::vector<PEInfo::PEExportEntry>& exports, bool is64Bit, const std::vector<FunctionInfo>& discoveredFuncs)
{
    functions_.clear();
    activeFunction_ = FunctionInfo();
    activePseudocode_.clear();
    hasAnalyzed_ = true;

    if (!discoveredFuncs.empty())
    {
        functions_ = discoveredFuncs;
    }
    else if (!insns.empty())
    {
        FunctionInfo fn;
        fn.name = "DriverEntry_or_Main";
        fn.startAddress = insns[0].address;
        fn.size = (uint32_t)(insns.size() * 4);
        fn.cyclomaticComplexity = 5;
        functions_.push_back(fn);
    }
    if (!functions_.empty())
        activeFunction_ = functions_[0];
}

void IDAProPanel::SelectFunction(Application& app, uint64_t funcAddress)
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
    if (!activeFunction_.name.empty() && activeFunction_.name[0] != 's')
    {
        // Preserve existing meaningful name from function list
        for (const auto& f : functions_)
        {
            if (f.startAddress == funcAddress && !f.name.empty())
            {
                activeFunction_.name = f.name;
                break;
            }
        }
    }
    else
    {
        for (const auto& f : functions_)
        {
            if (f.startAddress == funcAddress && !f.name.empty())
            {
                activeFunction_.name = f.name;
                break;
            }
        }
    }

    activePseudocode_ = app.functionAnalyzer.GeneratePseudocode(activeFunction_, app.is64Bit);
    app.NavigateToAddress(funcAddress);

    // Update XREF counts for active function
    auto xrefs = app.xrefScanner.FindXRefsTo(funcAddress);
    activeFunction_.xrefCount = (int)xrefs.size();
}

void IDAProPanel::Render(Application& app)
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
        if (ImGui::BeginTabItem("Experimental Pseudocode"))
        {
            if (!app.isAttached)
                UIManager::EmptyState("Attach to a process to generate pseudocode.");
            else
                RenderDecompilerTab(app);
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
        if (ImGui::BeginTabItem("Developer Workspace (Experimental)"))
        {
            RenderScriptEditorTab(app);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
}

void IDAProPanel::RenderFunctionsTab(Application& app)
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

    if (ImGui::BeginTable("FunctionsTable", 6,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Function Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Blocks", ImGuiTableColumnFlags_WidthFixed, 65.0f);
        ImGui::TableSetupColumn("V(G)", ImGuiTableColumnFlags_WidthFixed, 55.0f);
        ImGui::TableSetupColumn("XREFs", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableHeadersRow();

        std::string filterLower = helpers::ToLower(filterText_);

        for (const auto& fn : functions_)
        {
            std::string addrStr = helpers::FormatAddress(fn.startAddress, app.is64Bit);
            if (!filterLower.empty() &&
                helpers::ToLower(fn.name).find(filterLower) == std::string::npos &&
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

            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.40f, 0.85f, 0.95f, 1.0f), "%s", fn.name.c_str());

            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%zu B", fn.size);

            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%zu", fn.cfg.basicBlocks.size());

            ImGui::TableSetColumnIndex(4);
            ImVec4 compColor = (fn.cyclomaticComplexity >= 10) ? ImVec4(1.0f, 0.4f, 0.4f, 1.0f) :
                               (fn.cyclomaticComplexity >= 5)  ? ImVec4(1.0f, 0.75f, 0.3f, 1.0f) :
                                                                 ImVec4(0.7f, 0.85f, 0.7f, 1.0f);
            ImGui::TextColored(compColor, "%d", fn.cyclomaticComplexity);

            ImGui::TableSetColumnIndex(5);
            ImGui::TextColored(ImVec4(0.85f, 0.65f, 0.95f, 1.0f), "%d", fn.xrefCount);
        }

        ImGui::EndTable();
    }
}

void IDAProPanel::RenderCFGTab(Application& app)
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

void IDAProPanel::RenderDecompilerTab(Application& app)
{
    if (activeFunction_.startAddress == 0 || activePseudocode_.empty())
    {
        ImGui::Spacing();
        ImGui::TextDisabled("No experimental pseudocode is available. Select a function from the Functions tab.");
        return;
    }

    if (ImGui::Button("Copy Pseudocode"))
    {
        ImGui::SetClipboardText(activePseudocode_.c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Send to AI Copilot for Complete Refinement"))
    {
        std::string req = "Review this experimental C-like pseudocode generated for " +
                          activeFunction_.name + ":\n\n```c\n" + activePseudocode_ + "\n```";
        app.aiService.Send(req, nullptr);
    }
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.00f, 0.90f, 0.46f, 1.0f), "OpenReverse experimental output");

    ImGui::Separator();

    if (UIManager::GetMonoFont())
        ImGui::PushFont(UIManager::GetMonoFont());

    ImGui::BeginChild("PseudocodeTextWindow", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextUnformatted(activePseudocode_.c_str());
    ImGui::EndChild();

    if (UIManager::GetMonoFont())
        ImGui::PopFont();
}

void IDAProPanel::RenderXRefsTab(Application& app)
{
    if (xrefTargetAddress_ != 0)
    {
        snprintf(xrefAddressInput_, sizeof(xrefAddressInput_), "%llX",
                 static_cast<unsigned long long>(xrefTargetAddress_));
        currentXrefs_ = app.xrefScanner.FindXRefsTo(xrefTargetAddress_);
        xrefModeTo_ = true;
        xrefTargetAddress_ = 0;
    }

    ImGui::Text("Address:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(160.0f);
    ImGui::InputText("##xrefaddr", xrefAddressInput_, sizeof(xrefAddressInput_));
    ImGui::SameLine();

    auto resolveAddr = [&](const char* input) -> uint64_t {
        if (!input || input[0] == '\0') return activeFunction_.startAddress;
        uint64_t addr = helpers::ParseAddress(input);
        if (addr != 0) return addr;

        std::string lowerInput = helpers::ToLower(input);
        for (const auto& s : app.stringResults)
        {
            if (helpers::ToLower(s.value) == lowerInput ||
                helpers::ToLower(s.value).find(lowerInput) != std::string::npos)
            {
                return s.address;
            }
        }
        for (const auto& fn : functions_)
        {
            if (helpers::ToLower(fn.name) == lowerInput ||
                helpers::ToLower(fn.name).find(lowerInput) != std::string::npos)
            {
                return fn.startAddress;
            }
        }
        return activeFunction_.startAddress;
    };

    if (ImGui::Button("Find XREFs TO Address"))
    {
        uint64_t addr = resolveAddr(xrefAddressInput_);
        currentXrefs_ = app.xrefScanner.FindXRefsTo(addr);
        if (currentXrefs_.empty() && xrefAddressInput_[0] != '\0')
            currentXrefs_ = app.xrefScanner.SearchXRefsByText(xrefAddressInput_);
        xrefModeTo_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Find XREFs FROM Address"))
    {
        uint64_t addr = resolveAddr(xrefAddressInput_);
        currentXrefs_ = app.xrefScanner.FindXRefsFrom(addr);
        if (currentXrefs_.empty() && xrefAddressInput_[0] != '\0')
            currentXrefs_ = app.xrefScanner.SearchXRefsByText(xrefAddressInput_);
        xrefModeTo_ = false;
    }
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.70f, 0.85f, 0.95f, 1.0f), "Found %zu references", currentXrefs_.size());

    ImGui::Separator();

    if (currentXrefs_.empty())
    {
        ImGui::Spacing();
        ImGui::TextDisabled("No XREFs found. Analyze the active module or choose another address.");
        return;
    }

    if (ImGui::BeginTable("XRefsTable", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Direction", ImGuiTableColumnFlags_WidthFixed, 75.0f);
        ImGui::TableSetupColumn("From Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("To Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& xr : currentXrefs_)
        {
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            ImGui::TextColored(xrefModeTo_ ? ImVec4(0.35f, 0.85f, 0.45f, 1.0f) : ImVec4(0.95f, 0.65f, 0.35f, 1.0f),
                               xrefModeTo_ ? "UP (To)" : "DOWN (From)");

            ImGui::TableSetColumnIndex(1);
            std::string fromStr = helpers::FormatAddress(xr.fromAddress, app.is64Bit);
            if (ImGui::Selectable(fromStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
            {
                app.NavigateToAddress(xr.fromAddress);
            }

            ImGui::TableSetColumnIndex(2);
            std::string toStr = helpers::FormatAddress(xr.toAddress, app.is64Bit);
            ImGui::TextColored(ImVec4(0.60f, 0.80f, 0.95f, 1.0f), "%s", toStr.c_str());

            ImGui::TableSetColumnIndex(3);
            const char* typeStr = (xr.type == XRefType::Call) ? "CALL" :
                                  (xr.type == XRefType::Jump) ? "JUMP" :
                                  (xr.type == XRefType::Lea)  ? "LEA" :
                                  (xr.type == XRefType::Read) ? "READ" :
                                  (xr.type == XRefType::ReadWrite) ? "R/W" : "WRITE";
            ImVec4 typeColor = (xr.type == XRefType::Call) ? ImVec4(0.00f, 0.90f, 1.0f, 1.0f) :
                               (xr.type == XRefType::Jump) ? ImVec4(1.0f, 0.67f, 0.25f, 1.0f) :
                                                             ImVec4(0.75f, 0.85f, 0.75f, 1.0f);
            ImGui::TextColored(typeColor, "%s", typeStr);

            ImGui::TableSetColumnIndex(4);
            ImGui::TextColored(ImVec4(0.85f, 0.87f, 0.90f, 1.0f), "%s", xr.instructionText.c_str());
        }

        ImGui::EndTable();
    }
}

void IDAProPanel::RenderScriptEditorTab(Application& app)
{
    ImGui::TextColored(ImVec4(1.0f, 0.70f, 0.25f, 1.0f), "[EXPERIMENTAL SCRIPT EDITOR]");
    ImGui::SameLine();
    ImGui::TextDisabled("| Editing and AI assistance only; execution and publishing are not implemented");
    ImGui::Separator();

    ImGui::BeginDisabled();
    ImGui::Button("Run Script (Not Implemented)");
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Ask AI (With Script & Selected Context)"))
    {
        scriptLog_ += "[*] Sending the script and selected analysis context to the configured AI provider...\n";
        std::string prompt = std::string(devAiPrompt_);
        if (prompt.empty()) prompt = "Audit this script and suggest improvement heuristics for reverse engineering.";
        std::string fullContextPrompt = "Script Code:\n```cpp\n" + std::string(scriptBuffer_) + "\n```\nTarget Binary Functions Count: " +
                                        std::to_string(functions_.size()) + "\nUser Request: " + prompt;

        app.aiService.Send(fullContextPrompt, nullptr, app.GetAIContextSummary());
        devAiResponse_ = "The configured AI provider is analyzing the script and selected context...";
    }
    ImGui::SameLine();
    ImGui::BeginDisabled();
    ImGui::Button("Publish (Not Implemented)");
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Load Sample Heuristic"))
    {
        snprintf(scriptBuffer_, sizeof(scriptBuffer_),
                  "// OpenReverse Draft: Cobalt Strike / OLLVM Analysis Heuristic\n"
                 "void OnAnalyzeModule(openreverse::Application& app, std::vector<openreverse::FunctionInfo>& funcs) {\n"
                 "    for (auto& fn : funcs) {\n"
                 "        if (fn.cyclomaticComplexity > 15 && fn.name.find(\"sub_\") == 0) {\n"
                 "            fn.name = \"c2_beacon_handler_\" + helpers::FormatAddress(fn.startAddress, true);\n"
                 "        }\n"
                 "    }\n"
                 "}\n");
        if (textEditorPtr_) {
            textEditorPtr_->SetText(scriptBuffer_);
        }
        scriptLog_ += "[*] Loaded Cobalt Strike / OLLVM sample heuristic into editor buffer.\n";
    }

    ImGui::Separator();

    // 2-Column Split Layout: Code Editor (Left 58%) | AI Context Chat & Execution Log (Right 42%)
    ImGui::Columns(2, "DevStudioSplit", true);
    ImGui::SetColumnWidth(0, ImGui::GetWindowWidth() * 0.58f);

    // Left Column: Script Editor Buffer (Paris-main Syntax Highlighting TextEditor)
    ImGui::TextColored(ImVec4(0.00f, 0.90f, 1.0f, 1.0f), "Analysis Script Draft (Syntax Highlighted):");
    if (!textEditorPtr_) {
        textEditorPtr_ = new TextEditor();
        textEditorPtr_->SetLanguageDefinition(TextEditor::LanguageDefinition::CPlusPlus());
        textEditorPtr_->SetPalette(TextEditor::GetDarkPalette());
        textEditorPtr_->SetText(scriptBuffer_);
        textEditorPtr_->SetShowWhitespaces(false);
    }
    textEditorPtr_->Render("##ParisMainCodeEditor", ImVec2(-FLT_MIN, ImGui::GetContentRegionAvail().y - 10.0f), true);
    std::string editorTxt = textEditorPtr_->GetText();
    snprintf(scriptBuffer_, sizeof(scriptBuffer_), "%s", editorTxt.c_str());

    ImGui::NextColumn();

    // Right Column: AI Assistant Chat + Context & Execution Log
    ImGui::TextColored(ImVec4(1.0f, 0.70f, 0.20f, 1.0f), "AI Assistant (Script & Selected Context):");
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##devprompt", "Ask AI to write heuristic or debug script...", devAiPrompt_, sizeof(devAiPrompt_));

    ImGui::BeginChild("DevAiResponseBox", ImVec2(0, 180), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextWrapped("%s", devAiResponse_.c_str());
    const auto& conv = app.aiService.Conversation();
    if (!conv.empty() && conv.back().role == "assistant")
    {
        ImGui::Separator();
        ImGui::TextColored(ImVec4(0.50f, 0.95f, 0.50f, 1.0f), "%s", conv.back().content.c_str());
    }
    ImGui::EndChild();

    ImGui::TextColored(ImVec4(0.70f, 0.85f, 0.95f, 1.0f), "Workspace Log:");
    ImGui::BeginChild("DevScriptLogBox", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextUnformatted(scriptLog_.c_str());
    ImGui::EndChild();

    ImGui::Columns(1);
}

}} // namespace openreverse::panels
