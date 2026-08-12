#include "console_panel.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/logger.h"
#include <imgui.h>
#include <sstream>

namespace openreverse { namespace panels {

void ConsolePanel::Render(Application& app)
{
    ImGui::Begin("Console", nullptr, ImGuiWindowFlags_None);
    const auto entries = Logger::Get().Snapshot();

    UIManager::BeginToolbar();
    if (ImGui::Button("Clear"))
        Logger::Get().Clear();
    ImGui::SameLine();
    if (ImGui::Button("Copy all"))
    {
        std::stringstream ss;
        for (const auto& e : entries)
        {
            const char* p = (e.level == LogLevel::Debug) ? "[DBG]" : (e.level == LogLevel::Info) ? "[INF]" : (e.level == LogLevel::Warning) ? "[WRN]" : "[ERR]";
            ss << e.timestamp << " " << p << " " << e.message << "\n";
        }
        ImGui::SetClipboardText(ss.str().c_str());
    }
    UIManager::ToolbarSeparator();
    ImGui::Checkbox("DBG", &showDebug_); ImGui::SameLine();
    ImGui::Checkbox("INF", &showInfo_); ImGui::SameLine();
    ImGui::Checkbox("WRN", &showWarning_); ImGui::SameLine();
    ImGui::Checkbox("ERR", &showError_);
    UIManager::ToolbarSeparator();
    ImGui::Text("Entries: %zu", entries.size());
    UIManager::EndToolbar();

    ImGui::Separator();

    ImGui::BeginChild("LogScroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    for (const auto& entry : entries)
    {
        bool show = (entry.level == LogLevel::Debug && showDebug_) ||
                    (entry.level == LogLevel::Info && showInfo_) ||
                    (entry.level == LogLevel::Warning && showWarning_) ||
                    (entry.level == LogLevel::Error && showError_);
        if (!show) continue;

        ImVec4 color;
        const char* prefix;
        switch (entry.level)
        {
            case LogLevel::Debug:   color = ImVec4(0.5f, 0.5f, 0.6f, 1.0f); prefix = "[DBG]"; break;
            case LogLevel::Info:    color = ImVec4(0.3f, 0.8f, 0.5f, 1.0f); prefix = "[INF]"; break;
            case LogLevel::Warning: color = ImVec4(0.9f, 0.8f, 0.2f, 1.0f); prefix = "[WRN]"; break;
            case LogLevel::Error:   color = ImVec4(0.9f, 0.3f, 0.3f, 1.0f); prefix = "[ERR]"; break;
            default:                color = ImVec4(0.8f, 0.8f, 0.8f, 1.0f); prefix = "[???]"; break;
        }
        ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.5f, 1.0f), "%s", entry.timestamp.c_str());
        ImGui::SameLine();
        ImGui::TextColored(color, "%s %s", prefix, entry.message.c_str());
    }

    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20.0f)
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();

    ImGui::End();
}

}} // namespace openreverse::panels
