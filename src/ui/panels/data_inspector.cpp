// ============================================================================
// OpenReverse - UI Panel: Data Inspector Implementation
// ============================================================================
#include "data_inspector.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include <imgui.h>
#include <cstring>
#include <cstdio>

namespace openreverse { namespace panels {

void DataInspectorPanel::Render(Application& app)
{
    ImGui::Begin("Data Inspector", nullptr, ImGuiWindowFlags_None);

    if (app.selectedBytes.empty())
    {
        UIManager::EmptyState("Click a byte in the Hex Editor to inspect.");
        ImGui::End();
        return;
    }

    UIManager::BeginToolbar();
    ImGui::TextColored(ImVec4(0.4f, 0.6f, 0.8f, 1.0f), "Address: %s",
        helpers::FormatAddress(app.currentAddress, app.is64Bit).c_str());
    ImGui::SameLine();
    if (ImGui::Button("Copy address"))
        ImGui::SetClipboardText(helpers::FormatAddress(app.currentAddress, app.is64Bit).c_str());
    UIManager::EndToolbar();
    ImGui::Separator();

    const uint8_t* data = app.selectedBytes.data();
    size_t sz = app.selectedBytes.size();

    auto ShowValue = [](const char* label, const char* value, ImVec4 color = ImVec4(0.85f, 0.87f, 0.9f, 1.0f)) {
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.7f, 1.0f), "%s", label);
        ImGui::TableSetColumnIndex(1);
        ImGui::TextColored(color, "%s", value);
        if (ImGui::BeginPopupContextItem("CopyValue"))
        {
            if (ImGui::MenuItem("Copy"))
                ImGui::SetClipboardText(value);
            ImGui::EndPopup();
        }
    };

    uint64_t ptrValue64 = 0;
    uint32_t ptrValue32 = 0;
    if (sz >= 8)
        memcpy(&ptrValue64, data, 8);
    if (sz >= 4)
        memcpy(&ptrValue32, data, 4);

    if (ImGui::BeginTable("DataTypes", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg))
    {
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        char buf[128];

        // Int8
        if (sz >= 1) {
            int8_t v; memcpy(&v, data, 1);
            snprintf(buf, sizeof(buf), "%d", v);
            ShowValue("Int8", buf);
        }
        // UInt8
        if (sz >= 1) {
            uint8_t v; memcpy(&v, data, 1);
            snprintf(buf, sizeof(buf), "%u (0x%02X)", v, v);
            ShowValue("UInt8", buf);
        }
        // Int16
        if (sz >= 2) {
            int16_t v; memcpy(&v, data, 2);
            snprintf(buf, sizeof(buf), "%d", v);
            ShowValue("Int16", buf);
        }
        // UInt16
        if (sz >= 2) {
            uint16_t v; memcpy(&v, data, 2);
            snprintf(buf, sizeof(buf), "%u (0x%04X)", v, v);
            ShowValue("UInt16", buf);
        }
        // Int32
        if (sz >= 4) {
            int32_t v; memcpy(&v, data, 4);
            snprintf(buf, sizeof(buf), "%d", v);
            ShowValue("Int32", buf);
        }
        // UInt32
        if (sz >= 4) {
            uint32_t v; memcpy(&v, data, 4);
            snprintf(buf, sizeof(buf), "%u (0x%08X)", v, v);
            ShowValue("UInt32", buf);
        }
        // Int64
        if (sz >= 8) {
            int64_t v; memcpy(&v, data, 8);
            snprintf(buf, sizeof(buf), "%lld", (long long)v);
            ShowValue("Int64", buf);
        }
        // UInt64
        if (sz >= 8) {
            uint64_t v; memcpy(&v, data, 8);
            snprintf(buf, sizeof(buf), "%llu (0x%016llX)", (unsigned long long)v, (unsigned long long)v);
            ShowValue("UInt64", buf);
        }
        // Float
        if (sz >= 4) {
            float v; memcpy(&v, data, 4);
            snprintf(buf, sizeof(buf), "%.7g", v);
            ShowValue("Float", buf, ImVec4(0.9f, 0.8f, 0.4f, 1.0f));
        }
        // Double
        if (sz >= 8) {
            double v; memcpy(&v, data, 8);
            snprintf(buf, sizeof(buf), "%.15g", v);
            ShowValue("Double", buf, ImVec4(0.9f, 0.8f, 0.4f, 1.0f));
        }
        // Bool
        if (sz >= 1) {
            ShowValue("Bool", data[0] ? "true" : "false",
                data[0] ? ImVec4(0.3f, 0.9f, 0.4f, 1.0f) : ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
        }
        // Hex bytes
        {
            std::string hex = helpers::BytesToHex(data, sz < 8 ? sz : 8);
            ShowValue("Hex", hex.c_str(), ImVec4(0.5f, 0.8f, 0.7f, 1.0f));
        }

        ImGui::EndTable();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Text("Follow pointer");
    if (sz >= (size_t)(app.is64Bit ? 8 : 4))
    {
        uint64_t ptrVal = app.is64Bit ? ptrValue64 : (uint64_t)ptrValue32;
        char ptrStr[32];
        if (app.is64Bit)
            snprintf(ptrStr, sizeof(ptrStr), "0x%016llX", (unsigned long long)ptrVal);
        else
            snprintf(ptrStr, sizeof(ptrStr), "0x%08X", (unsigned int)ptrVal);
        ImGui::TextColored(ImVec4(0.6f, 0.7f, 0.9f, 1.0f), "%s", ptrStr);
        ImGui::SameLine();
        if (ImGui::Button("Go to address"))
        {
            if (ptrVal != 0)
                app.NavigateToAddress(ptrVal);
        }
    }
    else
        ImGui::TextColored(ImVec4(0.45f, 0.45f, 0.5f, 1.0f), "Select 4+ bytes (32-bit) or 8+ bytes (64-bit)");

    ImGui::End();
}

}} // namespace openreverse::panels
