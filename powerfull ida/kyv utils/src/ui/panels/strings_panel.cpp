// ============================================================================
// KYV - UI Panel: Strings Panel Implementation
// ============================================================================
#include "strings_panel.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include <imgui.h>

namespace kyv { namespace panels {

void StringsPanel::Render(Application& app)
{
    ImGui::Begin("Strings", nullptr, ImGuiWindowFlags_None);

    UIManager::BeginToolbar();
    ImGui::Text("Min length");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(50.0f);
    ImGui::InputInt("##minlen", &minLength_, 0, 0);
    if (minLength_ < 2) minLength_ = 2;
    UIManager::ToolbarSeparator();
    ImGui::Checkbox("ASCII", &scanAscii_);
    ImGui::SameLine();
    ImGui::Checkbox("Unicode", &scanUnicode_);
    UIManager::ToolbarSeparator();
    bool canScan = app.isAttached;
    if (!canScan) ImGui::BeginDisabled();
    if (ImGui::Button("Scan"))
    {
        auto regions = app.memoryReader.GetCommittedRegions();
        results_.clear();
        for (const auto& r : regions)
        {
            if (r.state != MEM_COMMIT || (r.protect & PAGE_GUARD) || r.protect == PAGE_NOACCESS)
                continue;
            auto partial = app.stringScanner.Scan(app.processHandle,
                r.baseAddress, r.baseAddress + r.size,
                minLength_, scanAscii_, scanUnicode_, 5000 - (int)results_.size());
            results_.insert(results_.end(), partial.begin(), partial.end());
            if (results_.size() >= 5000) break;
        }
    }
    if (!canScan) ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.5f, 0.7f, 0.5f, 1.0f), "%zu found", results_.size());
    UIManager::ToolbarSeparator();
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##strfilter", "Filter strings...", filterText_, sizeof(filterText_));
    UIManager::EndToolbar();

    ImGui::Separator();

    if (!app.isAttached)
    {
        UIManager::EmptyState("Attach to a process to scan for ASCII/Unicode strings.");
        ImGui::End();
        return;
    }

    if (!results_.empty() && ImGui::BeginTable("StringsTable", 4,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        std::string filter = helpers::ToLower(filterText_);

        for (size_t i = 0; i < results_.size(); ++i)
        {
            const auto& sr = results_[i];
            if (!filter.empty() && helpers::ToLower(sr.value).find(filter) == std::string::npos &&
                helpers::ToLower(sr.category).find(filter) == std::string::npos)
                continue;

            ImGui::PushID((int)i);
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            std::string addr = helpers::FormatAddress(sr.address, app.is64Bit);
            if (ImGui::Selectable(addr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                app.NavigateToAddress(sr.address);
            if (ImGui::BeginPopupContextItem("StringCtx"))
            {
                if (ImGui::MenuItem("Go to address"))
                    app.NavigateToAddress(sr.address);
                if (ImGui::MenuItem("Find XREFs to this string (X)"))
                {
                    app.idaProPanel.OpenXrefsForAddress(sr.address);
                    ImGui::SetWindowFocus("IDA Studio / Functions & CFG");
                }
                if (ImGui::MenuItem("Copy string value"))
                    ImGui::SetClipboardText(sr.value.c_str());
                if (ImGui::MenuItem("Add to Game Offsets"))
                    app.AddOffsetFromAddress(sr.address, sr.value.substr(0, 32));
                ImGui::EndPopup();
            }

            ImGui::TableSetColumnIndex(1);
            ImVec4 catColor = (sr.riskLevel == 3) ? ImVec4(1.0f, 0.35f, 0.35f, 1.0f) :
                              (sr.riskLevel == 2) ? ImVec4(1.0f, 0.72f, 0.28f, 1.0f) :
                              (sr.riskLevel == 1) ? ImVec4(0.40f, 0.80f, 0.90f, 1.0f) :
                                                    ImVec4(0.60f, 0.65f, 0.70f, 1.0f);
            ImGui::TextColored(catColor, "%s", sr.category.c_str());

            ImGui::TableSetColumnIndex(2);
            const char* enc = (sr.encoding == StringEncoding::ASCII) ? "ASCII" : "UTF-16";
            ImVec4 encColor = (sr.encoding == StringEncoding::ASCII)
                ? ImVec4(0.5f, 0.8f, 0.5f, 1.0f) : ImVec4(0.5f, 0.5f, 0.9f, 1.0f);
            ImGui::TextColored(encColor, "%s", enc);

            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(ImVec4(0.85f, 0.87f, 0.90f, 1.0f), "%s", sr.value.c_str());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    ImGui::End();
}

}} // namespace kyv::panels
