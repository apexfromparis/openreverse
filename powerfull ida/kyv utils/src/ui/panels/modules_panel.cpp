// ============================================================================
// KYV - UI Panel: Modules Panel Implementation
// ============================================================================

#include "modules_panel.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include <imgui.h>

namespace kyv { namespace panels {

void ModulesPanel::Render(Application& app)
{
    ImGui::Begin("Modules", nullptr, ImGuiWindowFlags_None);

    UIManager::BeginToolbar();
    if (ImGui::Button("Refresh"))
    {
        if (app.isAttached)
            app.moduleManager.RefreshModules(app.processHandle);
        cachedExports_.clear();
        selectedModule_ = -1;
    }
    UIManager::ToolbarSeparator();
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##modfilter", "Filter modules...", filterText_, sizeof(filterText_));
    UIManager::EndToolbar();

    ImGui::Separator();

    if (!app.isAttached)
    {
        UIManager::EmptyState("Attach to a process to view loaded modules.");
        ImGui::End();
        return;
    }

    const auto& modules = app.moduleManager.GetModules();
    std::string filter = helpers::ToLower(filterText_);

    // Modules table
    float exportHeight = showExports_ ? ImGui::GetContentRegionAvail().y * 0.4f : 0;
    float tableHeight = ImGui::GetContentRegionAvail().y - exportHeight - 30;

    if (ImGui::BeginTable("ModulesTable", 4,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable,
        ImVec2(0, tableHeight)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (int i = 0; i < (int)modules.size(); ++i)
        {
            const auto& mod = modules[i];
            if (!filter.empty() && helpers::ToLower(mod.name).find(filter) == std::string::npos)
                continue;

            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            bool selected = (i == selectedModule_);
            if (ImGui::Selectable(mod.name.c_str(), selected,
                ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
            {
                selectedModule_ = i;
                if (ImGui::IsMouseDoubleClicked(0))
                {
                    app.NavigateToAddress(mod.baseAddress);
                }
            }

            // Right-click context menu
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1))
            {
                selectedModule_ = i;
                ImGui::OpenPopup("ModuleCtx");
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.4f, 0.6f, 0.8f, 1.0f), "%s",
                helpers::FormatAddress(mod.baseAddress, app.is64Bit).c_str());

            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", helpers::FormatSize(mod.size).c_str());

            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, 1.0f), "%s", mod.path.c_str());
        }

        ImGui::EndTable();
    }

    // Context menu
    if (ImGui::BeginPopup("ModuleCtx"))
    {
        if (selectedModule_ >= 0 && selectedModule_ < (int)modules.size())
        {
            const auto& mod = modules[selectedModule_];
            ImGui::Text("%s", mod.name.c_str());
            ImGui::Separator();
            if (ImGui::MenuItem("Go to Base"))
                app.NavigateToAddress(mod.baseAddress);
            if (ImGui::MenuItem("View Exports"))
            {
                cachedExports_ = app.moduleManager.GetExports(app.processHandle, mod.baseAddress);
                showExports_ = true;
            }
            if (ImGui::MenuItem("Copy Base Address"))
                ImGui::SetClipboardText(helpers::FormatAddress(mod.baseAddress, app.is64Bit).c_str());
        }
        ImGui::EndPopup();
    }

    // Exports sub-panel
    if (showExports_ && selectedModule_ >= 0)
    {
        ImGui::Separator();
        ImGui::Text("Exports (%s) - %zu functions",
            modules[selectedModule_].name.c_str(), cachedExports_.size());

        if (ImGui::SmallButton("Close##exports"))
            showExports_ = false;

        if (ImGui::BeginTable("ExportsTable", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
            ImVec2(0, 0)))
        {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150.0f);
            ImGui::TableSetupColumn("Ordinal", ImGuiTableColumnFlags_WidthFixed, 65.0f);
            ImGui::TableHeadersRow();

            for (const auto& exp : cachedExports_)
            {
                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                if (ImGui::Selectable(exp.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                {
                    app.NavigateToAddress(exp.address);
                }

                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(ImVec4(0.4f, 0.6f, 0.8f, 1.0f), "%s",
                    helpers::FormatAddress(exp.address, app.is64Bit).c_str());

                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%d", exp.ordinal);
            }

            ImGui::EndTable();
        }
    }

    ImGui::Text("Total modules: %zu", modules.size());

    ImGui::End();
}

}} // namespace kyv::panels
