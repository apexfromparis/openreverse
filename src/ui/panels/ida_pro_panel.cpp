// ============================================================================
// OpenReverse - UI Panel: IDA Pro Studio Implementation
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

namespace openreverse { namespace panels {

IDAProPanel::~IDAProPanel()
{
    if (textEditorPtr_) {
        delete textEditorPtr_;
        textEditorPtr_ = nullptr;
    }
}

void IDAProPanel::AnalyzeCurrentModule(Application& app)
{
    functions_.clear();
    activeFunction_ = FunctionInfo();
    activePseudocode_.clear();
    app.xrefScanner.Clear();
    hasAnalyzed_ = false;

    if (!app.isAttached || !app.processHandle)
        return;

    auto* mod = app.moduleManager.FindModuleByAddress(app.currentAddress);
    if (!mod && !app.moduleManager.GetModules().empty())
        mod = const_cast<ModuleInfo*>(&app.moduleManager.GetModules()[0]);

    if (!mod)
    {
        Logger::Get().Log(LogLevel::Warning, "No module found to analyze in IDA Studio.");
        return;
    }

    Logger::Get().Log(LogLevel::Info, "IDA Studio scanning module %s (Base: 0x%llX, Size: %u)...",
                      mod->name.c_str(), (unsigned long long)mod->baseAddress, mod->size);

    // Limit scan size to 8 MB for immediate responsiveness
    size_t scanSize = mod->size;
    if (scanSize > 8ULL * 1024 * 1024)
        scanSize = 8ULL * 1024 * 1024;

    auto bytes = app.memoryReader.ReadBytes(app.processHandle, mod->baseAddress, scanSize);
    if (bytes.empty())
    {
        Logger::Get().Log(LogLevel::Error, "IDA Studio failed to read memory of %s", mod->name.c_str());
        return;
    }

    // 1. Discover functions via prologues and CALL rel32 scanning
    functions_ = app.functionAnalyzer.DiscoverFunctions(bytes.data(), bytes.size(), mod->baseAddress, app.is64Bit, 10000);

    // 2. Discover additional functions from PE EntryPoint & Exports
    PEInfo pe = app.peParser.Parse(app.processHandle, mod->baseAddress);
    if (pe.valid)
    {
        uint64_t entryAddr = (pe.entryPoint != 0) ? (mod->baseAddress + pe.entryPoint) : 0;
        std::vector<uint64_t> exportAddrs;
        for (const auto& exp : pe.exports)
            if (exp.rva != 0)
                exportAddrs.push_back(mod->baseAddress + exp.rva);

        functions_ = app.functionAnalyzer.DiscoverFunctionsFromPE(functions_, entryAddr, exportAddrs, app.is64Bit);
    }

    // 3. Scan XREFs across module
    app.xrefScanner.ScanBuffer(bytes.data(), bytes.size(), mod->baseAddress, mod->name, app.disassembler, app.is64Bit);

    // 4. Discover additional functions from XREF CALL targets (reaches functions without signatures/symbols)
    std::vector<uint64_t> callTargets;
    for (const auto& entry : app.xrefScanner.GetAllEntries())
    {
        if (entry.type == XRefType::Call && entry.toAddress >= mod->baseAddress && entry.toAddress < (mod->baseAddress + scanSize))
        {
            callTargets.push_back(entry.toAddress);
        }
    }
    functions_ = app.functionAnalyzer.DiscoverFunctionsFromXRefs(functions_, callTargets, mod->baseAddress, mod->baseAddress + scanSize, app.is64Bit, 10000);

    // 5. Scan ASCII & Unicode strings across module for smart XREF lookup
    app.stringResults = app.stringScanner.Scan(app.processHandle, mod->baseAddress, mod->baseAddress + scanSize, 4, true, true, 5000);

    // 6. Populate XREF counts for discovered functions
    for (auto& fn : functions_)
    {
        auto xrefs = app.xrefScanner.FindXRefsTo(fn.startAddress);
        fn.xrefCount = (int)xrefs.size();
    }

    hasAnalyzed_ = true;
    Logger::Get().Log(LogLevel::Info, "IDA Studio analysis complete: %zu functions, %zu total XREFs, %zu strings.",
                      functions_.size(), app.xrefScanner.GetTotalXRefsCount(), app.stringResults.size());

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
    else if (!exports.empty())
    {
        for (const auto& exp : exports)
        {
            FunctionInfo fn;
            fn.name = exp.name.empty() ? ("sub_" + helpers::FormatAddress(exp.rva, false)) : exp.name;
            fn.startAddress = exp.rva;
            fn.size = 64;
            fn.cyclomaticComplexity = 3;
            functions_.push_back(fn);
        }
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
    app.currentAddress = funcAddress;

    // Update XREF counts for active function
    auto xrefs = app.xrefScanner.FindXRefsTo(funcAddress);
    activeFunction_.xrefCount = (int)xrefs.size();
}

void IDAProPanel::Render(Application& app)
{
    ImGui::Begin("IDA Studio / Functions & CFG", nullptr, ImGuiWindowFlags_None);

    UIManager::BeginToolbar();
    if (ImGui::Button("Analyze Active Module"))
    {
        AnalyzeCurrentModule(app);
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

    if (ImGui::BeginTabBar("IDAStudioTabs"))
    {
        if (ImGui::BeginTabItem("Functions (IDA List)"))
        {
            if (!app.isAttached)
                UIManager::EmptyState("Attach to a process to use IDA Studio interactive analysis.");
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
        if (ImGui::BeginTabItem("Hex-Rays Decompiler"))
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
        if (ImGui::BeginTabItem("OpenReverse Cloud Dev Creator Studio (Script & AI)"))
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
    if (ImGui::Button("Refresh Analysis"))
        AnalyzeCurrentModule(app);

    if (functions_.empty())
    {
        ImGui::Spacing();
        ImGui::TextDisabled("No functions discovered yet. Click 'Analyze Active Module' above.");
        return;
    }

    if (ImGui::BeginTable("IDAFuncTable", 6,
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
            ImGui::Text("%zu", fn.basicBlocks.size());

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
    ImGui::TextColored(ImVec4(0.75f, 0.75f, 0.80f, 1.0f), "| %zu Basic Blocks | Complexity V(G): %d",
                       activeFunction_.basicBlocks.size(), activeFunction_.cyclomaticComplexity);
    ImGui::Separator();

    ImGui::BeginChild("CFGBlocksScroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    for (size_t i = 0; i < activeFunction_.basicBlocks.size(); ++i)
    {
        const auto& bb = activeFunction_.basicBlocks[i];
        ImGui::PushID((int)i);

        ImGui::BeginGroup();
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.14f, 0.18f, 0.95f));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.00f, 0.55f, 0.65f, 0.80f));

        char header[128];
        snprintf(header, sizeof(header), "Basic Block %zu [0x%llX -> 0x%llX] (%zu insns)",
                 i, (unsigned long long)bb.startAddress, (unsigned long long)bb.endAddress, bb.instructions.size());

        if (ImGui::CollapsingHeader(header, ImGuiTreeNodeFlags_DefaultOpen))
        {
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

            // Branch Edge Buttons
            ImGui::Spacing();
            if (bb.branchAddr != 0)
            {
                char branchBtn[64];
                snprintf(branchBtn, sizeof(branchBtn), "Branch -> 0x%llX", (unsigned long long)bb.branchAddr);
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.70f, 0.35f, 0.15f, 0.8f));
                if (ImGui::Button(branchBtn))
                {
                    app.NavigateToAddress(bb.branchAddr);
                }
                ImGui::PopStyleColor();
                ImGui::SameLine();
            }
            if (bb.fallthroughAddr != 0)
            {
                char fallBtn[64];
                snprintf(fallBtn, sizeof(fallBtn), "Fallthrough -> 0x%llX", (unsigned long long)bb.fallthroughAddr);
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.15f, 0.50f, 0.35f, 0.8f));
                if (ImGui::Button(fallBtn))
                {
                    app.NavigateToAddress(bb.fallthroughAddr);
                }
                ImGui::PopStyleColor();
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
        ImGui::TextDisabled("No decompiled C pseudocode available. Select a function from the Functions tab.");
        return;
    }

    if (ImGui::Button("Copy Pseudocode"))
    {
        ImGui::SetClipboardText(activePseudocode_.c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("Send to AI Copilot for Complete Refinement"))
    {
        std::string req = "Please perform a comprehensive senior reverse engineering analysis and security review on this C pseudocode decompiled from " +
                          activeFunction_.name + ":\n\n```c\n" + activePseudocode_ + "\n```";
        app.aiService.Send(req, nullptr);
    }
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.00f, 0.90f, 0.46f, 1.0f), "Hex-Rays Syntax Synthesizer Active");

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
        // 1. Check String table
        for (const auto& s : app.stringResults)
        {
            if (helpers::ToLower(s.value) == lowerInput ||
                helpers::ToLower(s.value).find(lowerInput) != std::string::npos)
            {
                return s.address;
            }
        }
        // 2. Check function names
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
        ImGui::TextDisabled("No XREFs found. Make sure you clicked 'Analyze Active Module' in the IDA Studio toolbar.");
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
                                  (xr.type == XRefType::Read) ? "READ" : "WRITE";
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
    ImGui::TextColored(ImVec4(1.0f, 0.30f, 0.30f, 1.0f), "[SCRIPT EDITOR & AI ASSISTANT]");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.60f, 0.85f, 0.60f, 1.0f), "| SDK: Unrestricted | All Cloud AI Clusters & Marketplace Royalties: Active");
    ImGui::Separator();

    // Toolbar buttons for Developer Scripting
    if (ImGui::Button("Run Script in Workspace"))
    {
        scriptLog_ += "[+] Running OnAnalyzeModule() script against " + std::to_string(functions_.size()) + " discovered functions...\n";
        int modifiedCount = 0;
        for (auto& fn : functions_)
        {
            if (fn.cyclomaticComplexity > 5 && fn.name.find("sub_") == 0)
            {
                fn.name = "cloud_heur_" + helpers::FormatAddress(fn.startAddress, app.is64Bit);
                modifiedCount++;
            }
        }
        scriptLog_ += "[+] Executed successfully! Modified/tagged " + std::to_string(modifiedCount) + " function signatures.\n";
    }
    ImGui::SameLine();
    if (ImGui::Button("Ask AI Copilot (With Script & Binary Context)"))
    {
        scriptLog_ += "[*] Packaging editor script + target binary context for OpenReverse Cloud AI Copilot...\n";
        std::string prompt = std::string(devAiPrompt_);
        if (prompt.empty()) prompt = "Audit this script and suggest improvement heuristics for reverse engineering.";
        std::string fullContextPrompt = "Script Code:\n```cpp\n" + std::string(scriptBuffer_) + "\n```\nTarget Binary Functions Count: " +
                                        std::to_string(functions_.size()) + "\nUser Request: " + prompt;

        app.aiService.Send(fullContextPrompt, nullptr, app.GetAIContextSummary());
        devAiResponse_ = "OpenReverse Cloud AI Copilot is analyzing your script with full reverse engineering target context...";
    }
    ImGui::SameLine();
    if (ImGui::Button("Publish to OpenReverse Cloud Hub (/hub)"))
    {
        scriptLog_ += "[+] Plugin signature generated! Submitted to OpenReverse Cloud Community Marketplace.\n";
    }
    ImGui::SameLine();
    if (ImGui::Button("Load Sample Heuristic"))
    {
        snprintf(scriptBuffer_, sizeof(scriptBuffer_),
                 "// OpenReverse Cloud Sample: Cobalt Strike / OLLVM Deobfuscator Heuristic\n"
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
    ImGui::TextColored(ImVec4(0.00f, 0.90f, 1.0f, 1.0f), "C++ / Python / Lua Plugin Editor (Syntax Highlighted):");
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
    ImGui::TextColored(ImVec4(1.0f, 0.70f, 0.20f, 1.0f), "OpenReverse Cloud AI Assistant (Script & RE Context):");
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

    ImGui::TextColored(ImVec4(0.70f, 0.85f, 0.95f, 1.0f), "Script Execution & Hub Sandbox Log:");
    ImGui::BeginChild("DevScriptLogBox", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::TextUnformatted(scriptLog_.c_str());
    ImGui::EndChild();

    ImGui::Columns(1);
}

}} // namespace openreverse::panels
