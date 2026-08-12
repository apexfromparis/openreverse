#include "offsets_panel.h"
#include "app/application.h"
#include "core/module_manager.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include "utils/logger.h"
#include <imgui.h>
#include <cstdio>
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
    ImGui::Begin("STRUCTURES", nullptr, ImGuiWindowFlags_None);
    UIManager::PanelHeader("STRUCTURES");

    if (!app.isAttached)
    {
        UIManager::EmptyState("Open a binary or attach to a process to inspect structures.");
        ImGui::End();
        return;
    }

    const ModuleAnalysisState* analysis = app.analysisDatabase.FindModuleContaining(app.currentAddress);
    if (!analysis && !app.analysisDatabase.GetModules().empty())
        analysis = &app.analysisDatabase.GetModules().begin()->second;

    const auto evidenceLevel = [](float score) {
        return score >= 0.8f ? "High evidence" : score >= 0.6f ? "Medium evidence" : "Low evidence";
    };

    if (!ImGui::BeginTabBar("StructureDataTabs"))
    {
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabItem("Structures"))
    {
        if (!analysis || analysis->structures.empty())
        {
            UIManager::EmptyState("No structures inferred for the current selection.");
        }
        else
        {
            for (const auto& structure : analysis->structures)
            {
                ImGui::PushID(structure.name.c_str());
                UIManager::SectionLabel(structure.name.c_str(), evidenceLevel(structure.confidence));
                ImGui::TextDisabled("Base %s  |  Function 0x%llX  |  Minimum size 0x%llX",
                    structure.baseRegister.c_str(), static_cast<unsigned long long>(structure.functionAddress),
                    static_cast<unsigned long long>(structure.estimatedSize));
                if (ImGui::BeginTable("StructureFields", 5,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
                {
                    ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 65.0f);
                    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 45.0f);
                    ImGui::TableSetupColumn("Reads", ImGuiTableColumnFlags_WidthFixed, 48.0f);
                    ImGui::TableSetupColumn("Writes", ImGuiTableColumnFlags_WidthFixed, 48.0f);
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
                ImGui::PopID();
            }
        }
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Globals"))
    {
        if (!analysis || analysis->globals.empty())
        {
            UIManager::EmptyState("No globals inferred for the current selection.");
        }
        else if (ImGui::BeginTable("InferredGlobals", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 65.0f);
            ImGui::TableSetupColumn("Module offset");
            ImGui::TableSetupColumn("Reads", ImGuiTableColumnFlags_WidthFixed, 48.0f);
            ImGui::TableSetupColumn("Writes", ImGuiTableColumnFlags_WidthFixed, 48.0f);
            ImGui::TableSetupColumn("Evidence", ImGuiTableColumnFlags_WidthFixed, 95.0f);
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
                ImGui::TextDisabled("%s", evidenceLevel(global.confidence));
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Offsets"))
    {
        if (offsets_.empty())
        {
            UIManager::EmptyState("No saved offsets. Add an address from Disassembly, Strings, Scanner, or Memory Map.");
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
        ImGui::TextDisabled("Dump size (hex)");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(70.0f);
        ImGui::InputText("##dumpsize", dumpSizeInput_, sizeof(dumpSizeInput_));
        ImGui::SameLine();
        if (ImGui::Button("Copy TXT")) ExportTxt();
        ImGui::SameLine();
        if (ImGui::Button("Copy C header")) ExportHeader();
        ImGui::SameLine();
        if (ImGui::Button("Copy JSON")) ExportJson();
        ImGui::EndTabItem();
    }

    ImGui::EndTabBar();

    ImGui::End();
}

}} // namespace openreverse::panels
