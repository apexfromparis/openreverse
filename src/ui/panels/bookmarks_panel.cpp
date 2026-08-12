// OpenReverse - UI Panel: Bookmarks Panel Implementation
#include "bookmarks_panel.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include <imgui.h>
#include <cstring>

namespace openreverse { namespace panels {

void BookmarksPanel::Render(Application& app)
{
    ImGui::Begin("Bookmarks", nullptr, ImGuiWindowFlags_None);

    UIManager::BeginToolbar();
    ImGui::Text("Address");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.0f);
    ImGui::InputText("##bkAddr", addrInput_, sizeof(addrInput_));
    ImGui::SameLine();
    ImGui::Text("Label");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100.0f);
    ImGui::InputText("##bkLabel", labelInput_, sizeof(labelInput_));
    ImGui::SameLine();
    if (ImGui::Button("Add"))
    {
        const auto address = helpers::TryParseAddress(addrInput_);
        if (address)
        {
            Bookmark bk;
            bk.address = *address;
            bk.label = strlen(labelInput_) > 0 ? labelInput_ : "Bookmark";
            bk.comment = commentInput_;
            bk.color = ImGui::GetColorU32(ImVec4(0.3f, 0.8f, 0.5f, 1.0f));
            bookmarks_.push_back(bk);
            memset(addrInput_, 0, sizeof(addrInput_));
            memset(labelInput_, 0, sizeof(labelInput_));
            memset(commentInput_, 0, sizeof(commentInput_));
        }
    }

    if (app.isAttached && ImGui::Button("Bookmark current"))
    {
        Bookmark bk;
        bk.address = app.currentAddress;
        bk.label = "Addr_" + helpers::FormatAddress(app.currentAddress, app.is64Bit);
        bk.color = ImGui::GetColorU32(ImVec4(0.3f, 0.6f, 0.9f, 1.0f));
        bookmarks_.push_back(bk);
    }
    UIManager::EndToolbar();

    ImGui::Separator();

    if (bookmarks_.empty())
    {
        UIManager::EmptyState("No bookmarks. Add an address or use \"Bookmark current\".");
    }
    else if (ImGui::BeginTable("BookmarksTable", 4,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Comment", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("##del", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableHeadersRow();

        int toDelete = -1;
        for (int i = 0; i < (int)bookmarks_.size(); ++i)
        {
            const auto& bk = bookmarks_[i];
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(bk.label.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                app.NavigateToAddress(bk.address);

            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.4f, 0.6f, 0.8f, 1.0f), "%s",
                helpers::FormatAddress(bk.address, app.is64Bit).c_str());

            ImGui::TableSetColumnIndex(2);
            ImGui::TextColored(ImVec4(0.55f, 0.55f, 0.6f, 1.0f), "%s", bk.comment.c_str());

            ImGui::TableSetColumnIndex(3);
            char delLabel[16];
            snprintf(delLabel, sizeof(delLabel), "X##%d", i);
            if (ImGui::SmallButton(delLabel))
                toDelete = i;
        }

        if (toDelete >= 0)
            bookmarks_.erase(bookmarks_.begin() + toDelete);

        ImGui::EndTable();
    }

    ImGui::Text("Total: %zu", bookmarks_.size());

    ImGui::End();
}

}} // namespace openreverse::panels
