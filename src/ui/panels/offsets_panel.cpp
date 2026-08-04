// ============================================================================
// OpenReverse - Offsets Panel Implementation
// ============================================================================

#include "offsets_panel.h"
#include "app/application.h"
#include "core/module_manager.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include "utils/logger.h"
#include <imgui.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace openreverse { namespace panels {

void OffsetsPanel::AddFromAddress(Application& app, uint64_t address, const std::string& defaultName)
{
    SavedOffset o;
    o.address = address;
    o.name = defaultName.empty() ? "Offset_" + helpers::FormatAddress(address, app.is64Bit) : defaultName;
    const ModuleInfo* mod = app.moduleManager.FindModuleByAddress(address);
    if (mod)
    {
        o.moduleName = mod->name;
        o.moduleBase = mod->baseAddress;
    }
    offsets_.push_back(o);
}

void OffsetsPanel::ExportTxt()
{
    // Format: Name = Module+0xXXX  (paster-friendly)
    std::string content;
    for (const auto& o : offsets_)
    {
        std::string offStr = o.moduleName.empty()
            ? helpers::FormatAddress(o.address, true)
            : helpers::FormatModuleOffset(o.moduleName, o.moduleBase, o.address, true);
        content += o.name + " = " + offStr + "\n";
    }
    if (!content.empty())
        ImGui::SetClipboardText(content.c_str());

    // Also try to save to file if we had a path - for now just clipboard
    // User can paste into a .txt
}

void OffsetsPanel::ExportHeader()
{
    // C/C++ style for pasters: #define Name 0x12345 or const uintptr_t Name = 0x12345;
    std::string content = "// Game offsets - paste into your cheat\n";
    content += "// Format: Module+offset (resolve at runtime with GetModuleBase + offset)\n\n";
    for (const auto& o : offsets_)
    {
        uint64_t off = o.moduleBase ? (o.address - o.moduleBase) : o.address;
        content += "const uintptr_t " + o.name + " = 0x";
        char buf[32];
        snprintf(buf, sizeof(buf), "%llX", (unsigned long long)off);
        content += buf;
        content += ";  // " + (o.moduleName.empty() ? "?" : o.moduleName) + "\n";
    }
    ImGui::SetClipboardText(content.c_str());
}

void OffsetsPanel::ExportJson()
{
    std::string content = "{\n  \"offsets\": [\n";
    for (size_t i = 0; i < offsets_.size(); ++i)
    {
        const auto& o = offsets_[i];
        std::string offStr = o.moduleName.empty()
            ? helpers::FormatAddress(o.address, true)
            : helpers::FormatModuleOffset(o.moduleName, o.moduleBase, o.address, true);
        content += "    { \"name\": \"" + o.name + "\", \"offset\": \"" + offStr + "\"";
        if (!o.comment.empty())
            content += ", \"comment\": \"" + o.comment + "\"";
        content += " }";
        if (i + 1 < offsets_.size()) content += ",";
        content += "\n";
    }
    content += "  ]\n}\n";
    ImGui::SetClipboardText(content.c_str());
}

void OffsetsPanel::Render(Application& app)
{
    ImGui::Begin("Game Offsets", nullptr, ImGuiWindowFlags_None);

    UIManager::BeginToolbar();
    ImGui::Text("Name");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputText("##offname", nameInput_, sizeof(nameInput_));
    ImGui::SameLine();
    ImGui::Text("Address");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.0f);
    ImGui::InputText("##offaddr", addrInput_, sizeof(addrInput_));
    ImGui::SameLine();
    if (ImGui::Button("Add"))
    {
        uint64_t addr = helpers::ParseAddress(addrInput_);
        if (addr != 0 || strlen(addrInput_) > 0)
        {
            AddFromAddress(app, addr, nameInput_[0] ? nameInput_ : "");
            nameInput_[0] = addrInput_[0] = 0;
        }
    }
    ImGui::SameLine();
    if (app.isAttached && ImGui::Button("Add current"))
    {
        AddFromAddress(app, app.currentAddress, nameInput_[0] ? nameInput_ : "");
        nameInput_[0] = 0;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Add current address (Hex/Disasm selection) as offset");
    UIManager::EndToolbar();

    ImGui::Separator();

    if (!app.isAttached)
    {
        UIManager::EmptyState("Attach to a process (e.g. game) to collect and export offsets.");
        ImGui::End();
        return;
    }

    if (offsets_.empty())
    {
        UIManager::EmptyState("No offsets yet. Use Add/Add current, or right-click addresses in Scanner/Disasm to add here.");
    }
    else if (ImGui::BeginTable("OffsetsTable", 4,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Module+Offset", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Comment", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (int i = 0; i < (int)offsets_.size(); ++i)
        {
            const auto& o = offsets_[i];
            ImGui::TableNextRow();
            bool selected = (i == selectedRow_);

            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(o.name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
            {
                selectedRow_ = i;
                app.NavigateToAddress(o.address);
            }
            if (ImGui::BeginPopupContextItem("OffsetCtx"))
            {
                if (ImGui::MenuItem("Go to"))
                    app.NavigateToAddress(o.address);
                std::string offStr = o.moduleName.empty()
                    ? helpers::FormatAddress(o.address, app.is64Bit)
                    : helpers::FormatModuleOffset(o.moduleName, o.moduleBase, o.address, app.is64Bit);
                if (ImGui::MenuItem("Copy offset (Module+0x...)"))
                    ImGui::SetClipboardText(offStr.c_str());
                if (ImGui::MenuItem("Copy as: Name = Module+0x..."))
                    ImGui::SetClipboardText((o.name + " = " + offStr).c_str());
                ImGui::Separator();
                if (ImGui::MenuItem("Dump memory to file..."))
                {
                    size_t dumpSize = (size_t)strtoull(dumpSizeInput_, nullptr, 16);
                    if (dumpSize == 0) dumpSize = 0x1000;
                    if (dumpSize > 64 * 1024 * 1024) dumpSize = 64 * 1024 * 1024;
                    char path[1024] = {};
                    char defaultName[128];
                    snprintf(defaultName, sizeof(defaultName), "%s_%s.bin", o.name.c_str(), offStr.c_str());
                    for (char* p = defaultName; *p; ++p) { if (*p == '+' || *p == ':') *p = '_'; }
                    if (helpers::OpenSaveFileDialog(path, sizeof(path), defaultName))
                    {
                        size_t written = app.memoryReader.DumpToFile(app.processHandle, o.address, dumpSize, path);
                        if (written > 0)
                            Logger::Get().Log(LogLevel::Info, "Dumped %zu bytes to %s", written, path);
                        else
                            Logger::Get().Log(LogLevel::Error, "Dump failed (read or write)");
                    }
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Remove"))
                {
                    offsets_.erase(offsets_.begin() + i);
                    if (selectedRow_ >= (int)offsets_.size()) selectedRow_ = -1;
                }
                ImGui::EndPopup();
            }

            ImGui::TableSetColumnIndex(1);
            std::string offStr = o.moduleName.empty()
                ? helpers::FormatAddress(o.address, app.is64Bit)
                : helpers::FormatModuleOffset(o.moduleName, o.moduleBase, o.address, app.is64Bit);
            ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.55f, 1.0f), "%s", offStr.c_str());

            ImGui::TableSetColumnIndex(2);
            ImGui::TextColored(ImVec4(0.45f, 0.6f, 0.8f, 1.0f), "%s",
                helpers::FormatAddress(o.address, app.is64Bit).c_str());

            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(ImVec4(0.55f, 0.55f, 0.6f, 1.0f), "%s", o.comment.c_str());
        }
        ImGui::EndTable();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Text("Dump size (hex bytes)");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    ImGui::InputText("##dumpsize", dumpSizeInput_, sizeof(dumpSizeInput_));
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Used by right-click -> Dump memory to file (default 0x1000)");
    ImGui::SameLine();
    ImGui::Text("Export:");
    ImGui::SameLine();
    if (ImGui::Button("Copy as .txt (Name = Module+0x...)"))
        ExportTxt();
    ImGui::SameLine();
    if (ImGui::Button("Copy as .h (C defines)"))
        ExportHeader();
    ImGui::SameLine();
    if (ImGui::Button("Copy as JSON"))
        ExportJson();
    if (!offsets_.empty())
        ImGui::SameLine(), ImGui::TextColored(ImVec4(0.5f, 0.65f, 0.5f, 1.0f), "%zu offsets", offsets_.size());

    ImGui::End();
}

}} // namespace openreverse::panels
