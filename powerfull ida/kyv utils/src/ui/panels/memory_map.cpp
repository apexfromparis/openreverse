// ============================================================================
// KYV - UI Panel: Memory Map Implementation
// ============================================================================

#include "memory_map.h"
#include "app/application.h"
#include "core/module_manager.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include "utils/logger.h"
#include <imgui.h>
#include <cstdio>

namespace kyv { namespace panels {

void MemoryMapPanel::Render(Application& app)
{
    ImGui::Begin("Memory Map", nullptr, ImGuiWindowFlags_None);

    UIManager::BeginToolbar();
    if (ImGui::Button("Refresh"))
    {
        if (app.isAttached)
            app.memoryReader.RefreshRegions(app.processHandle);
    }
    UIManager::ToolbarSeparator();
    ImGui::Checkbox("Show Free", &showFree_);
    ImGui::SameLine();
    ImGui::Checkbox("Exec Only (X/RWX)", &showExecOnly_);
    ImGui::SameLine();
    ImGui::Checkbox("Injected / Private Exec", &showPrivateExec_);
    UIManager::ToolbarSeparator();
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##mmfilter", "Filter regions...", filterText_, sizeof(filterText_));
    UIManager::EndToolbar();

    ImGui::Separator();

    if (!app.isAttached)
    {
        UIManager::EmptyState("Attach to a process to view the memory map.");
        ImGui::End();
        return;
    }

    const auto& regions = app.memoryReader.GetRegions();

    if (ImGui::BeginTable("MemMapTable", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Base Address", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Protect", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableHeadersRow();

        for (const auto& region : regions)
        {
            if (!showFree_ && region.state == MEM_FREE)
                continue;
            if (showExecOnly_ && !(region.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                continue;
            if (showPrivateExec_ && (region.type != MEM_PRIVATE || !(region.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))))
                continue;

            ImGui::TableNextRow();

            // Color by type
            ImVec4 rowColor;
            if (region.state == MEM_FREE)
                rowColor = ImVec4(0.3f, 0.3f, 0.3f, 1.0f);
            else if (region.type == MEM_IMAGE)
                rowColor = ImVec4(0.5f, 0.7f, 1.0f, 1.0f);
            else if (region.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
                rowColor = ImVec4(0.9f, 0.5f, 0.3f, 1.0f);
            else
                rowColor = ImVec4(0.8f, 0.8f, 0.85f, 1.0f);

            // Base Address (clickable, right-click menu)
            ImGui::TableSetColumnIndex(0);
            std::string addrStr = helpers::FormatAddress(region.baseAddress, app.is64Bit);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.6f, 0.8f, 1.0f));
            if (ImGui::Selectable(addrStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                app.NavigateToAddress(region.baseAddress);
            if (ImGui::BeginPopupContextItem("MemMapCtx"))
            {
                if (ImGui::MenuItem("Go to address"))
                    app.NavigateToAddress(region.baseAddress);
                if (ImGui::MenuItem("Copy address"))
                    ImGui::SetClipboardText(addrStr.c_str());
                const ModuleInfo* mod = app.moduleManager.FindModuleByAddress(region.baseAddress);
                if (mod)
                {
                    std::string offStr = helpers::FormatModuleOffset(mod->name, mod->baseAddress, region.baseAddress, app.is64Bit);
                    if (ImGui::MenuItem("Copy Module+Offset"))
                        ImGui::SetClipboardText(offStr.c_str());
                }
                if (ImGui::MenuItem("Add to Game Offsets"))
                    app.AddOffsetFromAddress(region.baseAddress);
                if (ImGui::MenuItem("Dump region to file..."))
                {
                    char path[1024] = {};
                    char defaultName[64];
                    snprintf(defaultName, sizeof(defaultName), "region_%llX_%llu.bin",
                        (unsigned long long)region.baseAddress, (unsigned long long)region.size);
                    if (helpers::OpenSaveFileDialog(path, sizeof(path), defaultName))
                    {
                        size_t toDump = (region.size > 64ULL * 1024 * 1024) ? (64ULL * 1024 * 1024) : (size_t)region.size;
                        size_t written = app.memoryReader.DumpToFile(app.processHandle,
                            region.baseAddress, toDump, path);
                        if (written > 0)
                            Logger::Get().Log(LogLevel::Info, "Dumped region %zu bytes to %s", written, path);
                        else
                            Logger::Get().Log(LogLevel::Error, "Dump failed");
                    }
                }
                ImGui::EndPopup();
            }
            ImGui::PopStyleColor();

            // Size
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%s", helpers::FormatSize(region.size).c_str());

            // State
            ImGui::TableSetColumnIndex(2);
            std::string state = helpers::StateToString(region.state);
            ImVec4 stateColor = (region.state == MEM_COMMIT)
                ? ImVec4(0.3f, 0.85f, 0.4f, 1.0f)
                : ImVec4(0.6f, 0.6f, 0.6f, 1.0f);
            ImGui::TextColored(stateColor, "%s", state.c_str());

            // Protection
            ImGui::TableSetColumnIndex(3);
            std::string prot = helpers::ProtectionToString(region.protect);
            bool hasExec = region.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
            ImVec4 protColor = hasExec
                ? ImVec4(0.9f, 0.5f, 0.3f, 1.0f)
                : ImVec4(0.7f, 0.7f, 0.75f, 1.0f);
            ImGui::TextColored(protColor, "%s", prot.c_str());

            // Type
            ImGui::TableSetColumnIndex(4);
            ImGui::TextColored(rowColor, "%s", helpers::TypeToString(region.type).c_str());
        }

        ImGui::EndTable();
    }

    ImGui::Text("Total regions: %zu", regions.size());

    ImGui::End();
}

}} // namespace kyv::panels
