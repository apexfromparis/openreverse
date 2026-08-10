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
    std::string content = "// OpenReverse module offsets\n\n";
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
    ImGui::Begin("Offsets & Structures", nullptr, ImGuiWindowFlags_None);

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
        UIManager::EmptyState("Open a binary or attach to a process to collect offsets.");
        ImGui::End();
        return;
    }

    const ModuleAnalysisState* analysis = app.analysisDatabase.FindModuleContaining(app.currentAddress);
    if (!analysis && !app.analysisDatabase.GetModules().empty())
        analysis = &app.analysisDatabase.GetModules().begin()->second;

    const size_t globalCount = analysis ? analysis->globals.size() : 0;
    char globalsHeader[64];
    snprintf(globalsHeader, sizeof(globalsHeader), "Inferred Globals (%zu)", globalCount);
    if (ImGui::CollapsingHeader(globalsHeader, ImGuiTreeNodeFlags_DefaultOpen))
    {
        if (!analysis || analysis->globals.empty())
        {
            ImGui::TextDisabled("No non-code global references have been inferred for this module.");
        }
        else if (ImGui::BeginTable("InferredGlobals", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("Module Offset");
            ImGui::TableSetupColumn("Reads", ImGuiTableColumnFlags_WidthFixed, 50.0f);
            ImGui::TableSetupColumn("Writes", ImGuiTableColumnFlags_WidthFixed, 50.0f);
            ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed, 75.0f);
            ImGui::TableHeadersRow();
            for (const auto& global : analysis->globals)
            {
                ImGui::PushID(static_cast<int>(global.moduleOffset));
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                if (ImGui::Selectable(global.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                    app.NavigateToAddress(global.address);
                if (ImGui::BeginPopupContextItem("GlobalCandidateContext"))
                {
                    if (ImGui::MenuItem("Add to saved offsets")) AddFromAddress(app, global.address, global.name);
                    if (ImGui::MenuItem("Go to reference") && !global.accessSites.empty())
                        app.NavigateToAddress(global.accessSites.front());
                    ImGui::EndPopup();
                }
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(global.sectionName.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%s+0x%llX", analysis->module.name.c_str(),
                            static_cast<unsigned long long>(global.moduleOffset));
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%zu", global.readCount + global.addressCount);
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%zu", global.writeCount);
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("%.0f%%", global.confidence * 100.0f);
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
    }

    const size_t structureCount = analysis ? analysis->structures.size() : 0;
    char structuresHeader[64];
    snprintf(structuresHeader, sizeof(structuresHeader), "Inferred Structures (%zu)", structureCount);
    if (ImGui::CollapsingHeader(structuresHeader, ImGuiTreeNodeFlags_DefaultOpen))
    {
        if (!analysis || analysis->structures.empty())
        {
            ImGui::TextDisabled("No repeated object-relative field layout has been inferred yet.");
        }
        else
        {
            for (const auto& structure : analysis->structures)
            {
                ImGui::PushID(structure.name.c_str());
                const bool open = ImGui::TreeNode(structure.name.c_str(), "%s  [%s in 0x%llX]  size >= 0x%llX, %.0f%%",
                    structure.name.c_str(), structure.baseRegister.c_str(),
                    static_cast<unsigned long long>(structure.functionAddress),
                    static_cast<unsigned long long>(structure.estimatedSize), structure.confidence * 100.0f);
                if (open)
                {
                    if (ImGui::BeginTable("StructureFields", 5,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
                    {
                        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 70.0f);
                        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 50.0f);
                        ImGui::TableSetupColumn("Reads", ImGuiTableColumnFlags_WidthFixed, 50.0f);
                        ImGui::TableSetupColumn("Writes", ImGuiTableColumnFlags_WidthFixed, 50.0f);
                        ImGui::TableSetupColumn("First access");
                        ImGui::TableHeadersRow();
                        for (const auto& field : structure.fields)
                        {
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("+0x%llX", static_cast<unsigned long long>(field.offset));
                            ImGui::TableSetColumnIndex(1);
                            ImGui::Text("%u", static_cast<unsigned>(field.size));
                            ImGui::TableSetColumnIndex(2);
                            ImGui::Text("%zu", field.readCount + field.addressCount);
                            ImGui::TableSetColumnIndex(3);
                            ImGui::Text("%zu", field.writeCount);
                            ImGui::TableSetColumnIndex(4);
                            if (!field.accessSites.empty())
                            {
                                const std::string address = helpers::FormatAddress(field.accessSites.front(), app.is64Bit);
                                if (ImGui::Selectable(address.c_str())) app.NavigateToAddress(field.accessSites.front());
                            }
                        }
                        ImGui::EndTable();
                    }
                    ImGui::TreePop();
                }
                ImGui::PopID();
            }
        }
    }

    ImGui::SeparatorText("Saved Offsets");

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
