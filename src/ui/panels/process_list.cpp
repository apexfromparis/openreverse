// ============================================================================
// OpenReverse - UI Panel: Process List Implementation
// ============================================================================

#include "process_list.h"
#include "app/application.h"
#include "core/automator.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"

#include <imgui.h>
#include <algorithm>

namespace openreverse { namespace panels {

void ProcessListPanel::Render(Application& app)
{
    ImGui::Begin("Processes", nullptr, ImGuiWindowFlags_None);

    UIManager::BeginToolbar();
    if (ImGui::Button("Refresh"))
        needsRefresh_ = true;
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Refresh process list (F5)");

    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.25f, 0.55f, 0.75f, 1.0f));
    if (ImGui::Button("  Open File / Driver (.sys)...  "))
    {
        app.ShowOpenFileDialog();
    }
    ImGui::PopStyleColor();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Open Windows File Manager to analyze any PE file or kernel driver (.sys) offline");

    UIManager::ToolbarSeparator();
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##filter", "Filter by name...", filterText_, sizeof(filterText_));
    UIManager::EndToolbar();

    ImGui::Separator();

    // Refresh process list
    if (needsRefresh_)
    {
        cachedProcesses_ = app.processManager.ListProcesses();

        // Sort by name
        std::sort(cachedProcesses_.begin(), cachedProcesses_.end(),
            [](const ProcessInfo& a, const ProcessInfo& b) {
                return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
            });

        needsRefresh_ = false;
    }

    // Process table
    if (ImGui::BeginTable("ProcessTable", 4,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 45.0f);
        ImGui::TableSetupColumn("Memory", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableHeadersRow();

        std::string filter = helpers::ToLower(filterText_);

        for (int i = 0; i < (int)cachedProcesses_.size(); ++i)
        {
            const auto& proc = cachedProcesses_[i];

            // Filter
            if (!filter.empty())
            {
                std::string nameLower = helpers::ToLower(proc.name);
                if (nameLower.find(filter) == std::string::npos)
                    continue;
            }

            ImGui::TableNextRow();

            bool isSelected = (i == selectedIdx_);
            bool isAttached = (app.isAttached && app.attachedPID == proc.pid);

            // Highlight attached process
            if (isAttached)
            {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                    ImGui::GetColorU32(ImVec4(0.1f, 0.35f, 0.2f, 0.5f)));
            }

            // PID
            ImGui::TableSetColumnIndex(0);
            char label[32];
            snprintf(label, sizeof(label), "%d", proc.pid);
            if (ImGui::Selectable(label, isSelected,
                ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
            {
                selectedIdx_ = i;
                if (ImGui::IsMouseDoubleClicked(0))
                {
                    app.AttachToProcess(proc.pid);
                    openreverse::Automator automator;
                    automator.AnalyzeProcess(app, proc.pid, proc.name);
                    app.idaProPanel.AnalyzeCurrentModule(app);
                    if (!app.idaProPanel.GetFunctions().empty())
                    {
                        app.currentAddress = app.idaProPanel.GetFunctions()[0].startAddress;
                        app.idaProPanel.SelectFunction(app, app.currentAddress);
                    }
                }
            }

            // Name
            ImGui::TableSetColumnIndex(1);
            if (isAttached)
                ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1.0f), "%s", proc.name.c_str());
            else
                ImGui::Text("%s", proc.name.c_str());

            // Architecture
            ImGui::TableSetColumnIndex(2);
            if (proc.is64bit)
                ImGui::TextColored(ImVec4(0.6f, 0.7f, 1.0f, 1.0f), "x64");
            else
                ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.5f, 1.0f), "x86");

            // Memory
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.6f, 1.0f), "%s",
                helpers::FormatSize(proc.memoryUsage).c_str());
        }

        ImGui::EndTable();
    }

    // Attach/detach buttons
    ImGui::Separator();
    if (selectedIdx_ >= 0 && selectedIdx_ < (int)cachedProcesses_.size())
    {
        if (ImGui::Button("Attach", ImVec2(80, 0)))
        {
            app.AttachToProcess(cachedProcesses_[selectedIdx_].pid);
            openreverse::Automator automator;
            automator.AnalyzeProcess(app, cachedProcesses_[selectedIdx_].pid, cachedProcesses_[selectedIdx_].name);
            app.idaProPanel.AnalyzeCurrentModule(app);
            if (!app.idaProPanel.GetFunctions().empty())
            {
                app.currentAddress = app.idaProPanel.GetFunctions()[0].startAddress;
                app.idaProPanel.SelectFunction(app, app.currentAddress);
            }
        }
        ImGui::SameLine();
    }

    if (app.isAttached)
    {
        if (ImGui::Button("Detach", ImVec2(80, 0)))
        {
            app.DetachFromProcess();
        }
    }

    ImGui::End();
}

}} // namespace openreverse::panels
