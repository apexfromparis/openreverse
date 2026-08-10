// ============================================================================
// OpenReverse - UI Panel: PE Viewer Implementation
// ============================================================================
#include "pe_viewer.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include <imgui.h>
#include <cstdio>

namespace openreverse { namespace panels {

void PEViewerPanel::Render(Application& app)
{
    ImGui::Begin("PE Header", nullptr, ImGuiWindowFlags_None);

    if (!app.isAttached)
    {
        UIManager::EmptyState("Open a binary or attach to a process to view PE headers and sections.");
        ImGui::End();
        return;
    }

    if (targetGeneration_ != app.targetGeneration)
    {
        targetGeneration_ = app.targetGeneration;
        peInfo_ = PEInfo{};
        loaded_ = false;
        loadedBase_ = 0;
        if (app.attachedPID == 0 && app.offlinePEInfo.valid)
        {
            peInfo_ = app.offlinePEInfo;
            loaded_ = true;
            loadedBase_ = peInfo_.imageBase;
        }
    }

    // Module selector
    const auto& modules = app.moduleManager.GetModules();
    if (ImGui::BeginCombo("Module##pe", loaded_ && loadedBase_ ? "Selected" : "Select module..."))
    {
        for (const auto& mod : modules)
        {
            char label[256];
            snprintf(label, sizeof(label), "%s (0x%llX)", mod.name.c_str(), (unsigned long long)mod.baseAddress);
            if (ImGui::Selectable(label))
            {
                peInfo_ = app.processHandle
                    ? app.peParser.Parse(app.processHandle, mod.baseAddress, mod.size)
                    : app.offlinePEInfo;
                loaded_ = peInfo_.valid;
                loadedBase_ = mod.baseAddress;
                targetGeneration_ = app.targetGeneration;
            }
        }
        ImGui::EndCombo();
    }

    if (!loaded_)
    {
        UIManager::EmptyState("Select a module from the dropdown to view its PE header.");
        ImGui::End();
        return;
    }

    ImGui::Separator();

    // NT Headers
    if (ImGui::CollapsingHeader("NT Headers", ImGuiTreeNodeFlags_DefaultOpen))
    {
        ImGui::Text("Machine:    0x%04X (%s)", peInfo_.machine,
            peInfo_.is64bit ? "AMD64" : "i386");
        ImGui::Text("Sections:   %d", peInfo_.numberOfSections);
        ImGui::Text("Timestamp:  0x%08X", peInfo_.timestamp);
        ImGui::Text("Image Size: %s", helpers::FormatSize(peInfo_.sizeOfImage).c_str());
        ImGui::Text("Entry Point: 0x%llX", (unsigned long long)(loadedBase_ + peInfo_.entryPoint));
        ImGui::Text("Image Base: 0x%llX", (unsigned long long)peInfo_.imageBase);

        if (ImGui::SmallButton("Go to Entry Point"))
            app.NavigateToAddress(loadedBase_ + peInfo_.entryPoint);
    }

    // Sections
    if (ImGui::CollapsingHeader("Sections", ImGuiTreeNodeFlags_DefaultOpen))
    {
        if (ImGui::BeginTable("SectionsTable", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg))
        {
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("VirtAddr", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("VirtSize", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("RawSize", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Chars", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableHeadersRow();

            for (const auto& sec : peInfo_.sections)
            {
                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                if (ImGui::Selectable(sec.name, false, ImGuiSelectableFlags_SpanAllColumns))
                    app.NavigateToAddress(loadedBase_ + sec.virtualAddress);

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("0x%08X", sec.virtualAddress);
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%s", helpers::FormatSize(sec.virtualSize).c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%s", helpers::FormatSize(sec.rawDataSize).c_str());
                ImGui::TableSetColumnIndex(4);

                std::string flags;
                if (sec.characteristics & IMAGE_SCN_MEM_READ)    flags += "R";
                if (sec.characteristics & IMAGE_SCN_MEM_WRITE)   flags += "W";
                if (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) flags += "X";
                if (sec.characteristics & IMAGE_SCN_CNT_CODE)    flags += " CODE";

                bool hasExec = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                ImGui::TextColored(hasExec ? ImVec4(0.9f, 0.5f, 0.3f, 1.0f) : ImVec4(0.7f, 0.7f, 0.75f, 1.0f),
                    "%s", flags.c_str());
            }
            ImGui::EndTable();
        }
    }

    // Imports
    if (ImGui::CollapsingHeader("Imports"))
    {
        for (const auto& imp : peInfo_.imports)
        {
            if (ImGui::TreeNode(imp.dllName.c_str()))
            {
                for (const auto& func : imp.functions)
                    ImGui::BulletText("%s", func.c_str());
                ImGui::TreePop();
            }
        }
    }

    // Exports
    if (ImGui::CollapsingHeader("Exports"))
    {
        if (peInfo_.exports.empty())
        {
            ImGui::TextDisabled("No exported functions found in this module.");
        }
        else if (ImGui::BeginTable("ExportsTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("Ordinal", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("RVA / Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
            ImGui::TableHeadersRow();

            for (const auto& exp : peInfo_.exports)
            {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("#%u", exp.ordinal);

                ImGui::TableSetColumnIndex(1);
                if (ImGui::Selectable(exp.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns) && !exp.isForwarder)
                {
                    app.NavigateToAddress(loadedBase_ + exp.rva);
                }

                ImGui::TableSetColumnIndex(2);
                if (exp.isForwarder)
                    ImGui::Text("Forwarder: %s", exp.forwarder.c_str());
                else
                    ImGui::Text("0x%08X (0x%llX)", exp.rva, (unsigned long long)(loadedBase_ + exp.rva));
            }
            ImGui::EndTable();
        }
    }

    ImGui::End();
}

}} // namespace openreverse::panels
