// ============================================================================
// OpenReverse - UI Panel: Disassembly View Implementation
// ============================================================================

#include "disasm_view.h"
#include "app/application.h"
#include "core/module_manager.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"

#include <imgui.h>
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace openreverse { namespace panels {

void DisasmViewPanel::SetAddress(uint64_t address)
{
    if (currentAddress_ != 0)
        history_.push_back(currentAddress_);
    currentAddress_ = address;
    snprintf(addressInput_, sizeof(addressInput_), "0x%llX", (unsigned long long)address);
    needsRefresh_ = true;
}

void DisasmViewPanel::RefreshDisassembly(Application& app)
{
    instructions_.clear();
    if (!app.isAttached || !app.disassembler.IsInitialized())
        return;

    // Read a chunk of memory
    size_t readSize = (size_t)numInstructions_ * 15; // max instruction size is ~15 bytes
    auto bytes = app.memoryReader.ReadBytes(app.processHandle, currentAddress_, readSize);

    if (!bytes.empty())
    {
        instructions_ = app.disassembler.Disassemble(
            bytes.data(), bytes.size(), currentAddress_, numInstructions_);
    }

    needsRefresh_ = false;
}

void DisasmViewPanel::Render(Application& app)
{
    ImGui::Begin("Disassembly", nullptr, ImGuiWindowFlags_None);

    UIManager::BeginToolbar();
    ImGui::Text("Address");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180.0f);
    if (ImGui::InputText("##disAddr", addressInput_, sizeof(addressInput_),
        ImGuiInputTextFlags_EnterReturnsTrue))
    {
        currentAddress_ = helpers::ParseAddress(addressInput_);
        needsRefresh_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Go"))
    {
        currentAddress_ = helpers::ParseAddress(addressInput_);
        needsRefresh_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh"))
        needsRefresh_ = true;
    if (!history_.empty())
    {
        ImGui::SameLine();
        if (ImGui::Button("Back"))
        {
            currentAddress_ = history_.back();
            history_.pop_back();
            snprintf(addressInput_, sizeof(addressInput_), "0x%llX", (unsigned long long)currentAddress_);
            needsRefresh_ = true;
        }
    }
    UIManager::ToolbarSeparator();
    if (ImGui::Checkbox("Intel syntax", &intelSyntax_))
    {
        app.disassembler.SetIntelSyntax(intelSyntax_);
        needsRefresh_ = true;
    }
    UIManager::ToolbarSeparator();
    ImGui::Text("Filter");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputTextWithHint("##disFilter", "Mnemonic or operands...", searchFilter_, sizeof(searchFilter_));
    UIManager::EndToolbar();

    ImGui::Separator();

    if (!app.isAttached)
    {
        UIManager::EmptyState("Attach to a process to disassemble code.");
        ImGui::End();
        return;
    }

    if (needsRefresh_)
        RefreshDisassembly(app);

    // ── Disassembly Table ──
    if (ImGui::BeginTable("DisasmTable", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("##bp", ImGuiTableColumnFlags_WidthFixed, 24.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 160.0f);
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        std::string filterLower = helpers::ToLower(searchFilter_);

        for (const auto& inst : instructions_)
        {
            std::string line = inst.mnemonic + " " + inst.operands;
            if (!filterLower.empty() && helpers::ToLower(line).find(filterLower) == std::string::npos)
                continue;

            ImGui::TableNextRow();

            bool isCurrent = (inst.address == app.currentAddress);
            if (isCurrent)
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                    ImGui::GetColorU32(ImVec4(0.00f, 0.32f, 0.38f, 0.35f)));

            // Dedicated gutter keeps future breakpoints and xrefs out of the code grid.
            ImGui::TableSetColumnIndex(0);
            ImGui::TextColored(isCurrent ? ImVec4(0.00f, 0.90f, 1.00f, 1.0f) : ImVec4(0.18f, 0.24f, 0.32f, 1.0f), "%s", isCurrent ? ">" : ".");

            // Address
            ImGui::TableSetColumnIndex(1);
            char addrStr[32];
            if (app.is64Bit)
                snprintf(addrStr, sizeof(addrStr), "%016llX", (unsigned long long)inst.address);
            else
                snprintf(addrStr, sizeof(addrStr), "%08X", (unsigned int)inst.address);

            if (ImFont* mono = UIManager::GetMonoFont())
                ImGui::PushFont(mono);
            ImGui::PushStyleColor(ImGuiCol_Text, isCurrent ? ImVec4(0.00f, 0.90f, 1.0f, 1.0f) : ImVec4(0.52f, 0.58f, 0.66f, 1.0f));
            if (ImGui::Selectable(addrStr, false, ImGuiSelectableFlags_SpanAllColumns))
                app.NavigateToAddress(inst.address);
            if (ImGui::BeginPopupContextItem("DisasmCtx"))
            {
                if (ImGui::MenuItem("Copy line"))
                {
                    char lineBuf[256];
                    snprintf(lineBuf, sizeof(lineBuf), "%s  %s  %s %s", addrStr,
                        helpers::BytesToHex(inst.bytes, inst.size).c_str(),
                        inst.mnemonic.c_str(), inst.operands.c_str());
                    ImGui::SetClipboardText(lineBuf);
                }
                if (ImGui::MenuItem("Copy address"))
                    ImGui::SetClipboardText(addrStr);
                const ModuleInfo* mod = app.moduleManager.FindModuleByAddress(inst.address);
                if (mod)
                {
                    std::string offStr = helpers::FormatModuleOffset(mod->name, mod->baseAddress, inst.address, app.is64Bit);
                    if (ImGui::MenuItem("Copy Module+Offset"))
                        ImGui::SetClipboardText(offStr.c_str());
                }
                if (ImGui::MenuItem("Find XREFs to this address (X)"))
                {
                    app.idaProPanel.OpenXrefsForAddress(inst.address);
                    ImGui::SetWindowFocus("IDA Studio / Functions & CFG");
                }
                if (ImGui::MenuItem("Decompile function in IDA Studio"))
                {
                    app.idaProPanel.SelectFunction(app, inst.address);
                    ImGui::SetWindowFocus("IDA Studio / Functions & CFG");
                }
                if (ImGui::MenuItem("Add to Game Offsets"))
                    app.AddOffsetFromAddress(inst.address);
                ImGui::EndPopup();
            }
            ImGui::PopStyleColor();
            if (UIManager::GetMonoFont())
                ImGui::PopFont();

            // Bytes
            ImGui::TableSetColumnIndex(2);
            if (UIManager::GetMonoFont())
                ImGui::PushFont(UIManager::GetMonoFont());
            std::string bytes = helpers::BytesToHex(inst.bytes, inst.size);
            ImGui::TextColored(ImVec4(0.45f, 0.45f, 0.55f, 1.0f), "%s", bytes.c_str());
            if (UIManager::GetMonoFont())
                ImGui::PopFont();

            // Mnemonic (color coded)
            ImGui::TableSetColumnIndex(3);
            ImVec4 mnemonicColor;
            if (inst.isCall)
                mnemonicColor = ImVec4(0.00f, 0.90f, 1.0f, 1.0f);  // cyan for calls
            else if (inst.isJump)
                mnemonicColor = ImVec4(1.0f, 0.67f, 0.25f, 1.0f);  // amber for jumps
            else if (inst.isRet)
                mnemonicColor = ImVec4(1.0f, 0.32f, 0.32f, 1.0f);  // coral for ret
            else if (inst.mnemonic == "nop")
                mnemonicColor = ImVec4(0.4f, 0.4f, 0.4f, 1.0f);  // dim for nops
            else if (inst.mnemonic == "push" || inst.mnemonic == "pop")
                mnemonicColor = ImVec4(0.00f, 0.90f, 0.46f, 1.0f);  // emerald for stack
            else if (inst.mnemonic == "mov" || inst.mnemonic == "lea")
                mnemonicColor = ImVec4(0.00f, 0.80f, 0.92f, 1.0f); // cyan for memory
            else
                mnemonicColor = ImVec4(0.75f, 0.75f, 0.8f, 1.0f); // light gray default

            ImGui::TextColored(mnemonicColor, "%s", inst.mnemonic.c_str());

            // Operands with deep inline symbol/target comment resolution
            ImGui::TableSetColumnIndex(4);
            ImGui::TextColored(ImVec4(0.7f, 0.75f, 0.8f, 1.0f), "%s", inst.operands.c_str());

            if ((inst.isJump || inst.isCall) && inst.targetAddress != 0)
            {
                ImGui::SameLine();
                auto* mod = app.moduleManager.FindModuleByAddress(inst.targetAddress);
                if (mod)
                {
                    uint64_t offset = inst.targetAddress - mod->baseAddress;
                    ImGui::TextColored(ImVec4(0.45f, 0.72f, 0.50f, 1.0f), "; -> %s+0x%llX", mod->name.c_str(), (unsigned long long)offset);
                }
                else
                {
                    ImGui::TextColored(ImVec4(0.45f, 0.72f, 0.50f, 1.0f), "; -> 0x%llX", (unsigned long long)inst.targetAddress);
                }
            }

            // Follow jump/call on double click
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0))
            {
                if ((inst.isJump || inst.isCall) && inst.targetAddress != 0)
                {
                    history_.push_back(currentAddress_);
                    currentAddress_ = inst.targetAddress;
                    snprintf(addressInput_, sizeof(addressInput_), "0x%llX", (unsigned long long)currentAddress_);
                    needsRefresh_ = true;
                }
            }

            // Tooltip for jumps/calls
            if (ImGui::IsItemHovered() && (inst.isJump || inst.isCall) && inst.targetAddress != 0)
            {
                ImGui::BeginTooltip();
                ImGui::Text("Target: %s", helpers::FormatAddress(inst.targetAddress, app.is64Bit).c_str());

                // Show which module the target belongs to
                auto* mod = app.moduleManager.FindModuleByAddress(inst.targetAddress);
                if (mod)
                    ImGui::Text("Module: %s", mod->name.c_str());

                ImGui::Text("Double-click to follow");
                ImGui::EndTooltip();
            }
        }

        ImGui::EndTable();
    }

    ImGui::End();
}

}} // namespace openreverse::panels
