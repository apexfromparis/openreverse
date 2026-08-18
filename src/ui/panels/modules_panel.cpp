#include "modules_panel.h"
#include "app/application.h"
#include "ui/workspace_ui.h"
#include "utils/helpers.h"
#include <imgui.h>

#include <limits>

namespace openreverse { namespace panels {

void ModulesPanel::Reset()
{
    selectedModule_ = -1;
    cachedExports_.clear();
    showExports_ = false;
}

void ModulesPanel::Render(Application& app)
{
    ImGui::Begin("MODULES", nullptr, ImGuiWindowFlags_None);
    workspace_ui::PanelHeader("MODULES");

    workspace_ui::BeginToolbar();
    if (ImGui::Button("Refresh"))
    {
        if (app.processHandle)
            app.moduleCatalog.RefreshModules(app.processHandle);
        cachedExports_.clear();
        selectedModule_ = -1;
    }
    workspace_ui::ToolbarSeparator();
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##modfilter", "Filter modules...", filterText_, sizeof(filterText_));
    workspace_ui::EndToolbar();

    ImGui::Separator();

    if (!app.isAttached)
    {
        workspace_ui::EmptyState("Attach to a process to view loaded modules.");
        ImGui::End();
        return;
    }

    const auto& modules = app.moduleCatalog.GetModules();
    std::string filter = helpers::ToLower(filterText_);

    float exportHeight = showExports_ ? ImGui::GetContentRegionAvail().y * 0.4f : 0;
    float tableHeight = ImGui::GetContentRegionAvail().y - exportHeight - 30;

    bool openModuleContext = false;
    ImGui::BeginChild("##ModuleRows", ImVec2(0, tableHeight), false);
    for (int i = 0; i < static_cast<int>(modules.size()); ++i)
    {
        const auto& mod = modules[i];
        if (!filter.empty() && helpers::ToLower(mod.name).find(filter) == std::string::npos)
            continue;

        ImGui::PushID(i);
        const ImVec2 marker = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddRect(
            ImVec2(marker.x + 2.0f, marker.y + 2.0f), ImVec2(marker.x + 10.0f, marker.y + 12.0f),
            IM_COL32(137, 151, 160, 255), 1.0f);
        ImGui::Dummy(ImVec2(14.0f, 14.0f));
        ImGui::SameLine(0.0f, 1.0f);

        const bool selected = i == selectedModule_;
        if (ImGui::Selectable(mod.name.c_str(), selected,
            ImGuiSelectableFlags_AllowDoubleClick))
        {
            selectedModule_ = i;
            if (ImGui::IsMouseDoubleClicked(0))
                app.NavigateToAddress(mod.baseAddress);
        }
        if (ImGui::IsItemHovered())
        {
            ImGui::BeginTooltip();
            ImGui::Text("%s", mod.name.c_str());
            ImGui::Text("Base: %s", helpers::FormatAddress(mod.baseAddress, app.is64Bit).c_str());
            ImGui::Text("Size: %s", helpers::FormatSize(mod.size).c_str());
            if (!mod.path.empty()) ImGui::TextWrapped("%s", mod.path.c_str());
            ImGui::EndTooltip();
        }
        if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1))
        {
            selectedModule_ = i;
            openModuleContext = true;
        }
        ImGui::PopID();
    }
    ImGui::EndChild();
    if (openModuleContext)
        ImGui::OpenPopup("ModuleCtx");

    if (ImGui::BeginPopup("ModuleCtx"))
    {
        if (selectedModule_ >= 0 && selectedModule_ < (int)modules.size())
        {
            const auto& mod = modules[selectedModule_];
            ImGui::Text("%s", mod.name.c_str());
            ImGui::Separator();
            if (ImGui::MenuItem("Go to Base"))
                app.NavigateToAddress(mod.baseAddress);
            if (ImGui::MenuItem("View Exports", nullptr, false, app.processHandle != nullptr))
            {
                const PEInfo pe = app.peParser.Parse(
                    app.processHandle, mod.baseAddress, mod.size);
                cachedExports_ = pe.valid ? pe.exports : std::vector<PEInfo::PEExportEntry>{};
                showExports_ = true;
            }
            if (ImGui::MenuItem("Copy Base Address"))
                ImGui::SetClipboardText(helpers::FormatAddress(mod.baseAddress, app.is64Bit).c_str());
        }
        ImGui::EndPopup();
    }

    if (showExports_ && selectedModule_ >= 0 && selectedModule_ < static_cast<int>(modules.size()))
    {
        const auto& selectedModule = modules[selectedModule_];
        ImGui::Separator();
        ImGui::Text("Exports (%s) - %zu functions",
            selectedModule.name.c_str(), cachedExports_.size());

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
                const uint64_t address = !exp.isForwarder &&
                    exp.rva <= (std::numeric_limits<uint64_t>::max)() - selectedModule.baseAddress
                    ? selectedModule.baseAddress + exp.rva : 0;
                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                if (ImGui::Selectable(exp.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                {
                    app.NavigateToAddress(address);
                }

                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(ImVec4(0.4f, 0.6f, 0.8f, 1.0f), "%s",
                    helpers::FormatAddress(address, app.is64Bit).c_str());

                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%d", exp.ordinal);
            }

            ImGui::EndTable();
        }
    }

    ImGui::Text("Total modules: %zu", modules.size());

    ImGui::End();
}

}} // namespace openreverse::panels
