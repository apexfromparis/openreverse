#include "process_list.h"
#include "app/application.h"
#include "ui/workspace_ui.h"
#include "utils/helpers.h"

#include <imgui.h>
#include <algorithm>

namespace openreverse { namespace panels {

void ProcessListPanel::Render(Application& app)
{
    ImGui::Begin("PROCESSES", nullptr, ImGuiWindowFlags_None);

    if (needsRefresh_)
    {
        cachedProcesses_ = app.processAccess.ListProcesses();
        std::sort(cachedProcesses_.begin(), cachedProcesses_.end(),
            [](const ProcessInfo& a, const ProcessInfo& b) {
                return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
            });
        needsRefresh_ = false;
    }

    char title[64];
    snprintf(title, sizeof(title), "PROCESSES (%zu)", cachedProcesses_.size());
    workspace_ui::PanelHeader(title, app.isAttached && app.attachedPID != 0 ? "ATTACHED" : nullptr);

    workspace_ui::BeginToolbar();
    if (ImGui::Button("Refresh"))
        needsRefresh_ = true;
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Refresh process list (F5)");

    workspace_ui::ToolbarSeparator();
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##filter", "Filter by name...", filterText_, sizeof(filterText_));
    workspace_ui::EndToolbar();

    ImGui::Separator();

    std::string filter = helpers::ToLower(filterText_);
    const float actionHeight = (selectedIdx_ >= 0 || app.isAttached) ? 30.0f : 0.0f;
    ImGui::BeginChild("##ProcessRows", ImVec2(0.0f, -actionHeight), false);
    for (int i = 0; i < static_cast<int>(cachedProcesses_.size()); ++i)
    {
        const auto& proc = cachedProcesses_[i];
        if (!filter.empty() && helpers::ToLower(proc.name).find(filter) == std::string::npos)
            continue;

        const bool selected = i == selectedIdx_;
        const bool attached = app.isAttached && app.attachedPID == proc.pid;
        ImGui::PushID(i);
        const ImVec2 marker = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddRect(
            ImVec2(marker.x + 2.0f, marker.y + 3.0f), ImVec2(marker.x + 10.0f, marker.y + 11.0f),
            attached ? IM_COL32(0, 141, 255, 255) : IM_COL32(126, 141, 151, 255), 1.0f, 0, 1.0f);
        ImGui::Dummy(ImVec2(14.0f, 14.0f));
        ImGui::SameLine(0.0f, 1.0f);

        char label[320];
        snprintf(label, sizeof(label), "%s  (%u)", proc.name.c_str(), proc.pid);
        if (ImGui::Selectable(label, selected,
            ImGuiSelectableFlags_AllowDoubleClick))
        {
            selectedIdx_ = i;
            if (ImGui::IsMouseDoubleClicked(0))
            {
                if (app.AttachToProcess(proc.pid))
                    app.analysisPanel.StartAnalyzeCurrentModule(app);
            }
        }
        if (ImGui::IsItemHovered())
        {
            ImGui::BeginTooltip();
            ImGui::Text("PID %u  |  %s", proc.pid, proc.is64bit ? "x64" : "x86");
            ImGui::Text("Memory: %s", proc.memoryUsage ? helpers::FormatSize(proc.memoryUsage).c_str() : "Unavailable");
            ImGui::EndTooltip();
        }
        ImGui::PopID();
    }
    ImGui::EndChild();

    ImGui::Separator();
    if (selectedIdx_ >= 0 && selectedIdx_ < (int)cachedProcesses_.size())
    {
        if (ImGui::Button("Attach", ImVec2(80, 0)))
        {
            if (app.AttachToProcess(cachedProcesses_[selectedIdx_].pid))
                app.analysisPanel.StartAnalyzeCurrentModule(app);
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
