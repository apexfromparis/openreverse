// ============================================================================
// KYV - UI Panel: Hex Editor Implementation
// ============================================================================

#include "hex_editor.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include "utils/logger.h"

#include <imgui.h>
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace kyv { namespace panels {

void HexEditorPanel::SetAddress(uint64_t address)
{
    currentAddress_ = address;
    snprintf(addressInput_, sizeof(addressInput_), "0x%llX", (unsigned long long)address);
    needsRefresh_ = true;
}

bool HexEditorPanel::HasSelection() const
{
    return selectionStart_ >= 0 && selectionEnd_ >= 0 && selectionStart_ < (int)buffer_.size() && selectionEnd_ < (int)buffer_.size();
}

void HexEditorPanel::CopySelectionHex()
{
    if (!HasSelection()) return;
    int lo = std::min(selectionStart_, selectionEnd_);
    int hi = std::max(selectionStart_, selectionEnd_);
    std::string hex = helpers::BytesToHex(buffer_.data() + lo, hi - lo + 1, " ");
    ImGui::SetClipboardText(hex.c_str());
}

void HexEditorPanel::CopySelectionCArray()
{
    if (!HasSelection()) return;
    int lo = std::min(selectionStart_, selectionEnd_);
    int hi = std::max(selectionStart_, selectionEnd_);
    std::string arr = helpers::BytesToCArray(buffer_.data() + lo, hi - lo + 1);
    ImGui::SetClipboardText(arr.c_str());
}

void HexEditorPanel::DoSearch()
{
    searchMatches_.clear();
    searchMatchIndex_ = -1;
    if (buffer_.empty()) return;

    std::vector<uint8_t> pattern;
    if (searchHex_)
    {
        std::string s = searchInput_;
        for (size_t i = 0; i < s.size(); )
        {
            while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
            if (i >= s.size()) break;
            if (i + 1 < s.size() && (s[i] == '?' || s[i] == '.') && (s[i+1] == '?' || s[i+1] == '.'))
            {
                pattern.push_back(0xFF);
                i += 2;
                if (i < s.size() && s[i] == ' ') ++i;
                continue;
            }
            if (i + 2 <= s.size())
            {
                int byte = 0;
                if (sscanf(s.c_str() + i, "%2X", &byte) == 1)
                {
                    pattern.push_back((uint8_t)byte);
                    i += 2;
                }
                else
                    ++i;
            }
            else
                break;
        }
    }
    else
    {
        for (const char* p = searchInput_; *p; ++p)
            pattern.push_back((uint8_t)*p);
    }
    if (pattern.empty()) return;

    for (size_t i = 0; i + pattern.size() <= buffer_.size(); ++i)
    {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j)
        {
            if (pattern[j] != 0xFF && buffer_[i + j] != pattern[j])
            {
                match = false;
                break;
            }
        }
        if (match)
            searchMatches_.push_back(i);
    }
    if (!searchMatches_.empty())
        searchMatchIndex_ = 0;
}

void HexEditorPanel::RefreshBuffer(Application& app)
{
    if (!app.isAttached || !app.processHandle)
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
    ImGui::Begin("Hex Editor", nullptr, ImGuiWindowFlags_None);

    UIManager::BeginToolbar();
    ImGui::Text("Address");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180.0f);
    if (ImGui::InputText("##addr", addressInput_, sizeof(addressInput_),
        ImGuiInputTextFlags_EnterReturnsTrue))
    {
        currentAddress_ = helpers::ParseAddress(addressInput_);
        needsRefresh_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Go"))
    {
        currentAddress_ = helpers::ParseAddress(addressInput_);
        needsRefresh_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh"))
        needsRefresh_ = true;
    UIManager::ToolbarSeparator();
    if (ImGui::Button("<<")) { currentAddress_ -= (uint64_t)bytesPerRow_ * numRows_; needsRefresh_ = true; }
    ImGui::SameLine();
    if (ImGui::Button("<")) { currentAddress_ -= bytesPerRow_; needsRefresh_ = true; }
    ImGui::SameLine();
    if (ImGui::Button(">")) { currentAddress_ += bytesPerRow_; needsRefresh_ = true; }
    ImGui::SameLine();
    if (ImGui::Button(">>")) { currentAddress_ += (uint64_t)bytesPerRow_ * numRows_; needsRefresh_ = true; }
    UIManager::ToolbarSeparator();
    ImGui::Text("Bytes/row");
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
    ImGui::Text("Rows");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(50.0f);
    if (ImGui::InputInt("##rows", &numRows_, 0, 0))
    {
        numRows_ = std::max(1, std::min(256, numRows_));
        needsRefresh_ = true;
    }
    UIManager::ToolbarSeparator();
    if (HasSelection())
    {
        if (ImGui::Button("Copy Hex"))
            CopySelectionHex();
        ImGui::SameLine();
        if (ImGui::Button("Copy C"))
            CopySelectionCArray();
        UIManager::ToolbarSeparator();
    }
    if (app.isAttached && ImGui::Button("Dump view to file"))
    {
        size_t size = (size_t)(bytesPerRow_ * numRows_);
        char path[1024] = {};
        char defaultName[64];
        snprintf(defaultName, sizeof(defaultName), "dump_%llX.bin", (unsigned long long)currentAddress_);
        if (helpers::OpenSaveFileDialog(path, sizeof(path), defaultName))
        {
            size_t written = app.memoryReader.DumpToFile(app.processHandle, currentAddress_, size, path);
            if (written > 0)
                Logger::Get().Log(LogLevel::Info, "Hex: dumped %zu bytes to %s", written, path);
            else
                Logger::Get().Log(LogLevel::Error, "Dump failed");
        }
    }
    UIManager::ToolbarSeparator();
    ImGui::Text("Search");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140.0f);
    ImGui::InputTextWithHint("##search", searchHex_ ? "Hex: 48 8B ?? ??  " : "ASCII text", searchInput_, sizeof(searchInput_));
    ImGui::SameLine();
    ImGui::Checkbox("Hex", &searchHex_);
    ImGui::SameLine();
    if (ImGui::Button("Find"))
        DoSearch();
    ImGui::SameLine();
    if (!searchMatches_.empty() && ImGui::Button("Next"))
    {
        searchMatchIndex_ = (searchMatchIndex_ + 1) % (int)searchMatches_.size();
        size_t off = searchMatches_[searchMatchIndex_];
        currentAddress_ = currentAddress_ + off;
        needsRefresh_ = true;
    }
    if (!searchMatches_.empty())
        ImGui::SameLine(), ImGui::TextColored(ImVec4(0.4f, 0.8f, 0.5f, 1.0f), "%zu matches", searchMatches_.size());
    UIManager::EndToolbar();

    ImGui::Separator();

    if (!app.isAttached)
    {
        UIManager::EmptyState("Attach to a process to view and edit memory.");
        ImGui::End();
        return;
    }

    // Refresh data
    if (needsRefresh_)
        RefreshBuffer(app);

    // Update address input display
    snprintf(addressInput_, sizeof(addressInput_), "0x%llX", (unsigned long long)currentAddress_);

    // Compact entropy strip gives the hex view an immediate visual read without
    // changing the underlying memory engine or pretending to classify bytes.
    ImGui::TextColored(ImVec4(0.52f, 0.58f, 0.66f, 1.0f), "ENTROPY");
    ImGui::SameLine();
    ImVec2 barMin = ImGui::GetCursorScreenPos();
    ImVec2 barMax = ImVec2(barMin.x + ImGui::GetContentRegionAvail().x - 12.0f, barMin.y + 8.0f);
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    float width = barMax.x - barMin.x;
    drawList->AddRectFilled(barMin, ImVec2(barMin.x + width * 0.34f, barMax.y), ImGui::GetColorU32(ImVec4(0.00f, 0.65f, 0.74f, 0.95f)), 3.0f);
    drawList->AddRectFilled(ImVec2(barMin.x + width * 0.34f, barMin.y), ImVec2(barMin.x + width * 0.72f, barMax.y), ImGui::GetColorU32(ImVec4(0.00f, 0.90f, 0.46f, 0.95f)), 3.0f);
    drawList->AddRectFilled(ImVec2(barMin.x + width * 0.72f, barMin.y), barMax, ImGui::GetColorU32(ImVec4(1.00f, 0.67f, 0.25f, 0.95f)), 3.0f);
    ImGui::Dummy(ImVec2(width, 9.0f));
    ImGui::TextColored(ImVec4(0.31f, 0.38f, 0.48f, 1.0f), "low 0-4.0     structured 4.0-6.8     packed / encrypted 6.8-8.0");

    // ── Hex Grid ──
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

    // Address column (highlight row containing current address)
    bool isCurrentRow = (app.currentAddress >= rowAddr && app.currentAddress < rowAddr + bytesPerRow_);
    ImVec4 addrColor = isCurrentRow ? ImVec4(0.2f, 0.7f, 1.0f, 1.0f) : ImVec4(0.4f, 0.6f, 0.8f, 1.0f);
    if (app.is64Bit)
        ImGui::TextColored(addrColor, "%016llX", (unsigned long long)rowAddr);
    else
        ImGui::TextColored(addrColor, "%08X        ", (unsigned int)rowAddr);

    // Hex bytes
    for (int col = 0; col < bytesPerRow_; ++col)
    {
        ImGui::SameLine();
        int idx = offset + col;

        if (hasData && idx < (int)buffer_.size())
        {
            uint8_t byte = buffer_[idx];

            // Color code by value
            ImVec4 color;
            if (byte == 0x00)
                color = ImVec4(0.30f, 0.30f, 0.35f, 1.0f); // dim for nulls
            else if (byte == 0xFF)
                color = ImVec4(0.8f, 0.3f, 0.3f, 1.0f);    // red for 0xFF
            else if (byte >= 0x20 && byte <= 0x7E)
                color = ImVec4(0.3f, 0.85f, 0.5f, 1.0f);   // green for printable
            else
                color = ImVec4(0.85f, 0.87f, 0.90f, 1.0f);  // white for other

            // Clickable hex byte
            char byteLabel[16];
            snprintf(byteLabel, sizeof(byteLabel), "%02X##%d", byte, idx);

            ImGui::PushStyleColor(ImGuiCol_Text, color);
            if (ImGui::SmallButton(byteLabel))
            {
                selectionStart_ = idx;
                selectionEnd_ = idx;
                app.currentAddress = rowAddr + col;

                // Update selected bytes for data inspector
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

}} // namespace kyv::panels
