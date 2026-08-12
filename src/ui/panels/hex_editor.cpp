#include "hex_editor.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"

#include <imgui.h>
#include <cstdio>
#include <cmath>

namespace openreverse { namespace panels {

void HexEditorPanel::SetAddress(uint64_t address)
{
    currentAddress_ = address;
    snprintf(addressInput_, sizeof(addressInput_), "0x%llX", (unsigned long long)address);
    needsRefresh_ = true;
}

void HexEditorPanel::Reset()
{
    currentAddress_ = 0;
    addressInput_[0] = '0';
    addressInput_[1] = '\0';
    buffer_.clear();
    selectionStart_ = -1;
    selectionEnd_ = -1;
    needsRefresh_ = true;
}

void HexEditorPanel::RefreshBuffer(Application& app)
{
    if (!app.isAttached)
    {
        buffer_.clear();
        return;
    }

    size_t totalBytes = (size_t)bytesPerRow_ * numRows_;
    buffer_ = app.memoryReader.ReadBytes(app.processHandle, currentAddress_, totalBytes);
    needsRefresh_ = false;
}

void HexEditorPanel::Render(Application& app)
{
    ImGui::Begin("HEX VIEW", nullptr, ImGuiWindowFlags_None);
    UIManager::PanelHeader("HEX VIEW");

    UIManager::BeginToolbar();
    ImGui::Text("Bytes");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(60.0f);
    const int bprOptions[] = { 8, 16, 32 };
    int bprIdx = (bytesPerRow_ == 8) ? 0 : (bytesPerRow_ == 32) ? 2 : 1;
    if (ImGui::Combo("##bpr", &bprIdx, "8\016\032\0"))
    {
        bytesPerRow_ = bprOptions[bprIdx];
        needsRefresh_ = true;
    }
    ImGui::SameLine();
    ImGui::Text("Go to");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180.0f);
    if (ImGui::InputText("##addr", addressInput_, sizeof(addressInput_),
        ImGuiInputTextFlags_EnterReturnsTrue))
    {
        if (const auto address = helpers::TryParseAddress(addressInput_))
        {
            currentAddress_ = *address;
            needsRefresh_ = true;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Go"))
    {
        if (const auto address = helpers::TryParseAddress(addressInput_))
        {
            currentAddress_ = *address;
            needsRefresh_ = true;
        }
    }
    UIManager::EndToolbar();

    ImGui::Separator();

    if (!app.isAttached)
    {
        UIManager::EmptyState("Open a binary or attach to a process to inspect bytes.");
        ImGui::End();
        return;
    }

    if (needsRefresh_)
        RefreshBuffer(app);

    snprintf(addressInput_, sizeof(addressInput_), "0x%llX", (unsigned long long)currentAddress_);

    float currentEntropy = CalculateEntropy(buffer_.data(), buffer_.size());
    ImGui::TextDisabled("Entropy %.2f / 8.00", currentEntropy);

    if (ImFont* mono = UIManager::GetMonoFont())
        ImGui::PushFont(mono);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.55f, 0.65f, 1.0f));
    ImGui::Text("  Address         ");
    ImGui::SameLine();
    for (int i = 0; i < bytesPerRow_; ++i)
    {
        ImGui::SameLine();
        ImGui::Text("%02X", i);
    }
    ImGui::SameLine();
    ImGui::Text("  ASCII");
    ImGui::PopStyleColor();

    ImGui::Separator();

    ImGui::BeginChild("HexView", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    for (int row = 0; row < numRows_; ++row)
    {
        uint64_t rowAddr = currentAddress_ + (uint64_t)row * bytesPerRow_;
        RenderHexRow(app, row, rowAddr);
    }

    ImGui::EndChild();

    if (UIManager::GetMonoFont())
        ImGui::PopFont();

    if (ImGui::IsWindowHovered())
    {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.0f)
        {
            int64_t delta = -(int64_t)(wheel * 3) * bytesPerRow_;
            if ((int64_t)currentAddress_ + delta >= 0)
                currentAddress_ += delta;
            needsRefresh_ = true;
        }
    }

    ImGui::End();
}

void HexEditorPanel::RenderHexRow(Application& app, int row, uint64_t rowAddr)
{
    int offset = row * bytesPerRow_;
    bool hasData = offset < (int)buffer_.size();

    bool isCurrentRow = (app.currentAddress >= rowAddr && app.currentAddress < rowAddr + bytesPerRow_);
    const ImVec2 rowStart = ImGui::GetCursorScreenPos();
    if (isCurrentRow)
        ImGui::GetWindowDrawList()->AddRectFilled(rowStart,
            ImVec2(rowStart.x + ImGui::GetContentRegionAvail().x,
                rowStart.y + ImGui::GetTextLineHeightWithSpacing()),
            IM_COL32(0, 48, 105, 225));
    ImVec4 addrColor = isCurrentRow ? ImVec4(0.76f, 0.89f, 1.0f, 1.0f) : ImVec4(0.4f, 0.6f, 0.8f, 1.0f);
    if (app.is64Bit)
        ImGui::TextColored(addrColor, "%016llX", (unsigned long long)rowAddr);
    else
        ImGui::TextColored(addrColor, "%08X        ", (unsigned int)rowAddr);

    for (int col = 0; col < bytesPerRow_; ++col)
    {
        ImGui::SameLine();
        int idx = offset + col;

        if (hasData && idx < (int)buffer_.size())
        {
            uint8_t byte = buffer_[idx];

            const ImVec4 color = byte == 0x00
                ? ImVec4(0.32f, 0.36f, 0.40f, 1.0f)
                : ImVec4(0.82f, 0.85f, 0.88f, 1.0f);

            // Plain selectable text keeps the grid dense; the old framed byte
            // buttons made every value look like an unrelated control.
            char byteLabel[16];
            snprintf(byteLabel, sizeof(byteLabel), "%02X##%d", byte, idx);

            ImGui::PushStyleColor(ImGuiCol_Text, color);
            const bool selected = selectionStart_ >= 0 && idx >= selectionStart_ && idx <= selectionEnd_;
            if (ImGui::Selectable(byteLabel, selected, ImGuiSelectableFlags_None,
                ImVec2(ImGui::CalcTextSize("FF").x + 3.0f, ImGui::GetTextLineHeight())))
            {
                selectionStart_ = idx;
                selectionEnd_ = idx;
                app.currentAddress = rowAddr + col;

                app.selectedBytes.clear();
                size_t remaining = buffer_.size() - idx;
                size_t copySize = remaining < 8 ? remaining : 8;
                app.selectedBytes.assign(buffer_.begin() + idx, buffer_.begin() + idx + copySize);
            }
            ImGui::PopStyleColor();
        }
        else
        {
            ImGui::TextColored(ImVec4(0.2f, 0.2f, 0.2f, 1.0f), "??");
        }

        // Separator between 8-byte groups
        if (col == 7)
        {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.2f, 0.2f, 0.3f, 1.0f), "|");
        }
    }

    // ASCII column
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.25f, 0.25f, 0.35f, 1.0f), " |");
    ImGui::SameLine();

    char asciiLine[64];
    for (int col = 0; col < bytesPerRow_ && col < 32; ++col)
    {
        int idx = offset + col;
        if (hasData && idx < (int)buffer_.size())
            asciiLine[col] = helpers::PrintableChar(buffer_[idx]);
        else
            asciiLine[col] = ' ';
    }
    int endCol = bytesPerRow_ < 32 ? bytesPerRow_ : 32;
    asciiLine[endCol] = 0;

    ImGui::TextColored(ImVec4(0.55f, 0.75f, 0.55f, 1.0f), "%s", asciiLine);
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.25f, 0.25f, 0.35f, 1.0f), "|");
}

float HexEditorPanel::CalculateEntropy(const uint8_t* data, size_t len) const
{
    if (!data || len == 0) return 0.0f;
    size_t counts[256] = {0};
    for (size_t i = 0; i < len; ++i)
        counts[data[i]]++;
    float entropy = 0.0f;
    for (int i = 0; i < 256; ++i)
    {
        if (counts[i] > 0)
        {
            float p = (float)counts[i] / (float)len;
            entropy -= p * log2f(p);
        }
    }
    return entropy;
}

}} // namespace openreverse::panels
