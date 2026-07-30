// ============================================================================
// KYV - UI Panel: Scanner Panel Implementation
// ============================================================================

#include "scanner_panel.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include <imgui.h>
#include <cstring>

namespace kyv { namespace panels {

void ScannerPanel::Render(Application& app)
{
    ImGui::Begin("Pattern Scanner", nullptr, ImGuiWindowFlags_None);

    UIManager::BeginToolbar();
    ImGui::Text("AOB pattern");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-120.0f);
    ImGui::InputTextWithHint("##pattern", "48 8B ?? ?? 74 0A  (?? = wildcard)", patternInput_, sizeof(patternInput_));
    bool canScan = app.isAttached && strlen(patternInput_) > 0;
    if (!canScan) ImGui::BeginDisabled();
    if (ImGui::Button("Scan"))
    {
        auto pattern = PatternScanner::ParsePattern(patternInput_);
        if (!pattern.empty())
        {
            auto regions = app.memoryReader.GetCommittedRegions();
            results_ = app.patternScanner.ScanRegions(app.processHandle, pattern, regions);
        }
    }
    if (!canScan) ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.5f, 0.7f, 0.5f, 1.0f), "%zu results", results_.size());
    UIManager::EndToolbar();

    ImGui::Separator();

    if (!app.isAttached)
    {
        UIManager::EmptyState("Attach to a process to scan for byte patterns (AOB).");
        ImGui::End();
        return;
    }

    // Results table
    if (!results_.empty() && ImGui::BeginTable("ScanResults", 2,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
        ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& res : results_)
        {
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            std::string addr = helpers::FormatAddress(res.address, app.is64Bit);
            if (ImGui::Selectable(addr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                app.NavigateToAddress(res.address);
            if (ImGui::BeginPopupContextItem("ScanResultCtx"))
            {
                if (ImGui::MenuItem("Go to"))
                    app.NavigateToAddress(res.address);
                auto* mod = app.moduleManager.FindModuleByAddress(res.address);
                if (mod)
                {
                    std::string offStr = helpers::FormatModuleOffset(mod->name, mod->baseAddress, res.address, app.is64Bit);
                    if (ImGui::MenuItem("Copy Module+Offset"))
                        ImGui::SetClipboardText(offStr.c_str());
                }
                if (ImGui::MenuItem("Add to Game Offsets"))
                    app.AddOffsetFromAddress(res.address);
                ImGui::EndPopup();
            }

            ImGui::TableSetColumnIndex(1);
            auto* mod = app.moduleManager.FindModuleByAddress(res.address);
            if (mod)
            {
                std::string offStr = helpers::FormatModuleOffset(mod->name, mod->baseAddress, res.address, app.is64Bit);
                ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.55f, 1.0f), "%s", offStr.c_str());
            }
            else
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "(unknown)");
        }

        ImGui::EndTable();
    }

    if (ImGui::Button("Clear Results"))
        results_.clear();

    ImGui::End();
}

}} // namespace kyv::panels
