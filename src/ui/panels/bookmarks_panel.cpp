#include "bookmarks_panel.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include <imgui.h>
#include <cstring>

namespace openreverse { namespace panels {

namespace {

const ModuleInfo* ActiveModule(const Application& app)
{
    const ModuleInfo* module = app.moduleManager.FindModuleByAddress(app.currentAddress);
    if (!module && !app.moduleManager.GetModules().empty())
        module = &app.moduleManager.GetModules().front();
    return module;
}

} // namespace

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
    ImGui::SetNextItemWidth(160.0f);
    ImGui::InputTextWithHint("##bkComment", "Comment", commentInput_, sizeof(commentInput_));
    ImGui::SameLine();
    if (app.targetKind != AnalysisTargetKind::LiveProcess && ImGui::Button("Add"))
    {
        const auto address = helpers::TryParseAddress(addrInput_);
        const ModuleInfo* module = ActiveModule(app);
        if (address && module)
        {
            const bool enteredRva = *address < module->size;
            const uint64_t absolute = enteredRva ? module->baseAddress + *address : *address;
            if (absolute < module->baseAddress || absolute >= module->baseAddress + module->size)
            {
                ImGui::OpenPopup("Bookmark address outside module");
            }
            else
            {
                ProjectBookmark bk;
                bk.rva = absolute - module->baseAddress;
                bk.label = strlen(labelInput_) > 0 ? labelInput_ : "Bookmark";
                bk.comment = commentInput_;
                bk.color = ImGui::GetColorU32(ImVec4(0.3f, 0.8f, 0.5f, 1.0f));
                app.analysisSession.AddBookmark(std::move(bk));
                memset(addrInput_, 0, sizeof(addrInput_));
                memset(labelInput_, 0, sizeof(labelInput_));
                memset(commentInput_, 0, sizeof(commentInput_));
            }
        }
    }

    if (app.isAttached && app.targetKind != AnalysisTargetKind::LiveProcess &&
        ImGui::Button("Bookmark current"))
    {
        const ModuleInfo* module = ActiveModule(app);
        if (module)
        {
            ProjectBookmark bk;
            bk.rva = app.currentAddress - module->baseAddress;
            bk.label = "Addr_" + helpers::FormatAddress(app.currentAddress, app.is64Bit);
            bk.color = ImGui::GetColorU32(ImVec4(0.3f, 0.6f, 0.9f, 1.0f));
            app.analysisSession.AddBookmark(std::move(bk));
        }
    }
    UIManager::EndToolbar();

    if (ImGui::BeginPopupModal("Bookmark address outside module", nullptr,
                               ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImGui::TextUnformatted("Enter an RVA or an address inside the active module.");
        if (ImGui::Button("OK")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    ImGui::Separator();

    const auto& bookmarks = app.analysisSession.Bookmarks();
    const ModuleInfo* module = ActiveModule(app);
    if (bookmarks.empty())
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
        for (int i = 0; i < static_cast<int>(bookmarks.size()); ++i)
        {
            const auto& bk = bookmarks[i];
            const uint64_t address = module ? module->baseAddress + bk.rva : bk.rva;
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(bk.label.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                app.NavigateToAddress(address);

            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(0.4f, 0.6f, 0.8f, 1.0f), "%s",
                helpers::FormatAddress(address, app.is64Bit).c_str());

            ImGui::TableSetColumnIndex(2);
            ImGui::TextColored(ImVec4(0.55f, 0.55f, 0.6f, 1.0f), "%s", bk.comment.c_str());

            ImGui::TableSetColumnIndex(3);
            char delLabel[16];
            snprintf(delLabel, sizeof(delLabel), "X##%d", i);
            if (ImGui::SmallButton(delLabel))
                toDelete = i;
        }

        if (toDelete >= 0)
            app.analysisSession.RemoveBookmark(static_cast<size_t>(toDelete));

        ImGui::EndTable();
    }

    ImGui::Text("Total: %zu", bookmarks.size());

    ImGui::End();
}

}} // namespace openreverse::panels
