// ============================================================================
// KYV - UI Panel: IDA Pro Studio Implementation
// ============================================================================

#include "ida_pro_panel.h"
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

namespace kyv { namespace panels {

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

    // 1. Discover functions
    functions_ = app.functionAnalyzer.DiscoverFunctions(bytes.data(), bytes.size(), mod->baseAddress, app.is64Bit, 1000);

    // 2. Scan XREFs across module
    app.xrefScanner.ScanBuffer(bytes.data(), bytes.size(), mod->baseAddress, mod->name, app.disassembler, app.is64Bit);

    // 3. Scan ASCII & Unicode strings across module for smart XREF lookup
    app.stringResults = app.stringScanner.Scan(app.processHandle, mod->baseAddress, mod->baseAddress + scanSize, 4, true, true, 5000);

    // 4. Populate XREF counts for discovered functions
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

void IDAProPanel::SelectFunction(Application& app, uint64_t funcAddress)
{
    if (!app.isAttached || !app.processHandle) return;

    auto* mod = app.moduleManager.FindModuleByAddress(funcAddress);
    uint64_t modBase = mod ? mod->baseAddress : (funcAddress & 0xFFFFFFFF00000000ULL);
    size_t readSize = 32768; // 32 KB function window

    auto bytes = app.memoryReader.ReadBytes(app.processHandle, modBase, readSize);
    if (bytes.empty())
    {
        // Fallback: read directly at funcAddress
        bytes = app.memoryReader.ReadBytes(app.processHandle, funcAddress, 8192);
        modBase = funcAddress;
    }

    activeFunction_ = app.functionAnalyzer.AnalyzeFunction(bytes.data(), bytes.size(), funcAddress, modBase, app.disassembler, app.is64Bit, 8192);
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

    if (!app.isAttached)
    {
        UIManager::EmptyState("Attach to a process to use IDA Studio interactive analysis.");
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabBar("IDAStudioTabs"))
    {
        if (ImGui::BeginTabItem("Functions (IDA List)"))
        {
            RenderFunctionsTab(app);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("CFG Basic Blocks"))
        {
            RenderCFGTab(app);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Hex-Rays Decompiler"))
        {
            RenderDecompilerTab(app);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("XREFs (Cross-References)"))
        {
            RenderXRefsTab(app);
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

}} // namespace kyv::panels
