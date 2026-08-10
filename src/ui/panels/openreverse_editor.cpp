#include "openreverse_editor.h"
#include "app/application.h"
#include "utils/logger.h"
#include <imgui.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

namespace openreverse {

namespace {

bool IsInsideWorkspace(const fs::path& workspace, const fs::path& candidate)
{
    std::error_code ec;
    const fs::path root = fs::weakly_canonical(workspace, ec);
    if (ec) return false;
    const fs::path target = fs::weakly_canonical(candidate, ec);
    if (ec) return false;
    const fs::path relative = target.lexically_relative(root);
    if (relative.empty() || relative.is_absolute()) return false;
    return *relative.begin() != "..";
}

} // namespace

OpenReverseEditorPanel::OpenReverseEditorPanel()
{
    textEditor_.SetLanguageDefinition(::TextEditor::LanguageDefinition::CPlusPlus());
    textEditor_.SetPalette(::TextEditor::GetDarkPalette());
    textEditor_.SetShowWhitespaces(false);
    textEditor_.SetReadOnly(false);
    workspaceDir_ = "openreverse_scripts";
}

OpenReverseEditorPanel::~OpenReverseEditorPanel()
{
}

void OpenReverseEditorPanel::EnsureDefaultFiles()
{
    if (initialized_)
        return;

    std::error_code ec;
    fs::create_directories(workspaceDir_ + "/user_scripts", ec);
    fs::create_directories(workspaceDir_ + "/decompiled_modules", ec);
    fs::create_directories(workspaceDir_ + "/plugins", ec);

    ScanWorkspaceFolder();
    initialized_ = true;

    if (!files_.empty() && openTabs_.empty())
    {
        OpenFileFromDisk(files_[0].path);
    }
}

void OpenReverseEditorPanel::ScanWorkspaceFolder()
{
    files_.clear();
    std::error_code ec;
    if (!fs::exists(workspaceDir_, ec))
        return;

    for (const auto& entry : fs::recursive_directory_iterator(workspaceDir_, ec))
    {
        if (ec) break;
        if (entry.is_regular_file())
        {
            std::string fullPath = entry.path().string();
            std::string filename = entry.path().filename().string();
            std::string parentDir = entry.path().parent_path().filename().string();
            if (parentDir == workspaceDir_ || parentDir.empty())
                parentDir = "ROOT";

            EditorFileNode node;
            node.name = filename;
            node.path = fullPath;
            node.category = parentDir;
            node.isDirectory = false;
            files_.push_back(node);
        }
    }
}

void OpenReverseEditorPanel::OpenFileFromDisk(const std::string& filepath)
{
    if (activeTabIdx_ >= 0 && activeTabIdx_ < static_cast<int>(openTabs_.size()))
    {
        auto& activeTab = openTabs_[activeTabIdx_];
        activeTab.currentText = textEditor_.GetText();
        activeTab.isDirty = activeTab.currentText != activeTab.initialText;
    }
    for (size_t i = 0; i < openTabs_.size(); ++i)
    {
        if (openTabs_[i].filepath == filepath)
        {
            activeTabIdx_ = (int)i;
            textEditor_.SetText(openTabs_[i].currentText);
            return;
        }
    }

    std::ifstream in(filepath, std::ios::binary);
    if (!in)
    {
        Logger::Get().Log(LogLevel::Error, "%s", ("Cannot read file from disk: " + filepath).c_str());
        return;
    }

    std::stringstream ss;
    ss << in.rdbuf();
    std::string content = ss.str();

    EditorTab tab;
    tab.filepath = filepath;
    tab.filename = fs::path(filepath).filename().string();
    tab.initialText = content;
    tab.currentText = content;
    tab.isDirty = false;

    openTabs_.push_back(tab);
    activeTabIdx_ = (int)openTabs_.size() - 1;
    textEditor_.SetText(content);
    currentSelectedPath_ = filepath;

    Logger::Get().Log(LogLevel::Info, "%s", ("Opened file from disk: " + tab.filename).c_str());
}

void OpenReverseEditorPanel::SaveActiveFileToDisk()
{
    if (activeTabIdx_ < 0 || activeTabIdx_ >= (int)openTabs_.size())
    {
        Logger::Get().Log(LogLevel::Warning, "[OpenReverse Editor] No active tab to save.");
        return;
    }

    EditorTab& tab = openTabs_[activeTabIdx_];
    std::string currentText = textEditor_.GetText();

    std::ofstream out(tab.filepath, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        Logger::Get().Log(LogLevel::Error, "%s", ("Failed to write file: " + tab.filepath).c_str());
        return;
    }

    out << currentText;
    tab.initialText = currentText;
    tab.currentText = currentText;
    tab.isDirty = false;

    Logger::Get().Log(LogLevel::Info, "%s", ("Saved file to disk: " + tab.filename).c_str());
}

void OpenReverseEditorPanel::CreateNewFileOnDisk(const std::string& filename, const std::string& folderName)
{
    if (filename.empty())
        return;

    const fs::path targetDir = fs::path(workspaceDir_) /
        (folderName.empty() ? fs::path("user_scripts") : fs::path(folderName));
    const fs::path fullPath = targetDir / filename;
    if (!IsInsideWorkspace(workspaceDir_, fullPath))
    {
        Logger::Get().Log(LogLevel::Error, "File path is outside the editor workspace");
        return;
    }

    std::error_code ec;
    fs::create_directories(targetDir, ec);
    if (ec)
    {
        Logger::Get().Log(LogLevel::Error, "Could not create editor folder");
        return;
    }

    if (fs::exists(fullPath, ec))
    {
        Logger::Get().Log(LogLevel::Warning, "%s", ("File already exists: " + filename).c_str());
        OpenFileFromDisk(fullPath.string());
        return;
    }

    std::ofstream out(fullPath);
    if (!out)
    {
        Logger::Get().Log(LogLevel::Error, "Could not create editor file");
        return;
    }
    out.close();

    ScanWorkspaceFolder();
    OpenFileFromDisk(fullPath.string());
    Logger::Get().Log(LogLevel::Info, "%s", ("Created file: " + fullPath.string()).c_str());
}

void OpenReverseEditorPanel::CreateNewFolderOnDisk(const std::string& folderName)
{
    if (folderName.empty())
        return;

    const fs::path targetDir = fs::path(workspaceDir_) / folderName;
    if (!IsInsideWorkspace(workspaceDir_, targetDir))
    {
        Logger::Get().Log(LogLevel::Error, "Folder path is outside the editor workspace");
        return;
    }
    std::error_code ec;
    fs::create_directories(targetDir, ec);
    if (ec)
    {
        Logger::Get().Log(LogLevel::Error, "Could not create editor folder");
        return;
    }
    ScanWorkspaceFolder();
    Logger::Get().Log(LogLevel::Info, "%s", ("Created folder: " + targetDir.string()).c_str());
}

void OpenReverseEditorPanel::DeleteFileFromDisk(const std::string& filepath)
{
    if (filepath.empty())
        return;
    if (!IsInsideWorkspace(workspaceDir_, filepath))
    {
        Logger::Get().Log(LogLevel::Error, "File path is outside the editor workspace");
        return;
    }
    const auto openTab = std::find_if(openTabs_.begin(), openTabs_.end(), [&](const EditorTab& tab) {
        return tab.filepath == filepath;
    });
    if (openTab != openTabs_.end() && openTab->isDirty)
    {
        Logger::Get().Log(LogLevel::Warning, "Save changes before deleting %s", openTab->filename.c_str());
        return;
    }

    std::error_code ec;
    if (fs::exists(filepath, ec))
    {
        fs::remove(filepath, ec);
        Logger::Get().Log(LogLevel::Info, "%s", ("Deleted file from disk: " + filepath).c_str());
    }

    for (auto it = openTabs_.begin(); it != openTabs_.end(); )
    {
        if (it->filepath == filepath)
        {
            it = openTabs_.erase(it);
        }
        else
        {
            ++it;
        }
    }
    if (activeTabIdx_ >= (int)openTabs_.size())
    {
        activeTabIdx_ = (int)openTabs_.size() - 1;
    }
    if (activeTabIdx_ >= 0)
    {
        textEditor_.SetText(openTabs_[activeTabIdx_].currentText);
    }
    else
    {
        textEditor_.SetText("");
    }

    ScanWorkspaceFolder();
}

void OpenReverseEditorPanel::RenameFileOnDisk(const std::string& oldPath, const std::string& newName)
{
    if (oldPath.empty() || newName.empty())
        return;

    std::error_code ec;
    fs::path oldP(oldPath);
    const fs::path newPath = oldP.parent_path() / newName;
    if (!IsInsideWorkspace(workspaceDir_, oldP) || !IsInsideWorkspace(workspaceDir_, newPath))
    {
        Logger::Get().Log(LogLevel::Error, "Rename path is outside the editor workspace");
        return;
    }

    if (fs::exists(oldP, ec))
    {
        fs::rename(oldP, newPath, ec);
    }
    if (ec)
    {
        Logger::Get().Log(LogLevel::Error, "Could not rename editor file");
        return;
    }
    Logger::Get().Log(LogLevel::Info, "%s", ("Renamed file to: " + newName).c_str());

    for (auto& tab : openTabs_)
    {
        if (tab.filepath == oldPath)
        {
            tab.filepath = newPath.string();
            tab.filename = newName;
        }
    }
    currentSelectedPath_ = newPath.string();
    ScanWorkspaceFolder();
}

void OpenReverseEditorPanel::PerformGlobalSearch()
{
    searchResults_.clear();
    if (searchQueryBuf_[0] == '\0')
        return;

    std::string query = searchQueryBuf_;
    for (const auto& f : files_)
    {
        std::ifstream in(f.path);
        if (!in) continue;

        std::string line;
        int lineNum = 1;
        while (std::getline(in, line))
        {
            if (line.find(query) != std::string::npos)
            {
                SearchResult res;
                res.filepath = f.path;
                res.filename = f.name;
                res.line = lineNum;
                res.matchingText = line;
                searchResults_.push_back(res);
            }
            lineNum++;
        }
    }
    Logger::Get().Log(LogLevel::Info, "[Search] Found %zu matches across workspace scripts.", searchResults_.size());
}

void OpenReverseEditorPanel::PerformGlobalReplace()
{
    if (searchQueryBuf_[0] == '\0')
        return;

    std::string query = searchQueryBuf_;
    std::string repl = replaceQueryBuf_;

    int totalReplaced = 0;
    for (const auto& f : files_)
    {
        std::ifstream in(f.path);
        if (!in) continue;

        std::stringstream ss;
        ss << in.rdbuf();
        std::string content = ss.str();
        in.close();

        size_t pos = 0;
        bool changed = false;
        while ((pos = content.find(query, pos)) != std::string::npos)
        {
            content.replace(pos, query.length(), repl);
            pos += repl.length();
            totalReplaced++;
            changed = true;
        }

        if (changed)
        {
            std::ofstream out(f.path, std::ios::binary | std::ios::trunc);
            out << content;
        }
    }

    ScanWorkspaceFolder();
    if (activeTabIdx_ >= 0 && activeTabIdx_ < (int)openTabs_.size())
    {
        OpenFileFromDisk(openTabs_[activeTabIdx_].filepath);
    }
    Logger::Get().Log(LogLevel::Info, "[Replace] Replaced %d occurrences across workspace scripts.", totalReplaced);
}

void OpenReverseEditorPanel::Render(Application& app, bool& p_open)
{
    if (!p_open)
        return;

    EnsureDefaultFiles();

    if (ImGui::IsKeyDown(ImGuiKey_LeftCtrl) && ImGui::IsKeyPressed(ImGuiKey_S, false))
    {
        SaveActiveFileToDisk();
    }
    if (ImGui::IsKeyDown(ImGuiKey_LeftCtrl) && ImGui::IsKeyPressed(ImGuiKey_F, false))
    {
        activeSidebarTab_ = 1;
    }
    ImGuiWindowFlags flags = ImGuiWindowFlags_None;
    if (app.isEditorFloating)
    {
        flags |= ImGuiWindowFlags_NoDocking;
    }
    ImGui::SetNextWindowSize(ImVec2(1100, 720), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("OpenReverse Editor", &p_open, flags))
    {
        ImGui::End();
        return;
    }

    RenderTopActionBar(app);

    float availW = ImGui::GetContentRegionAvail().x;
    float availH = ImGui::GetContentRegionAvail().y - 26.0f; // Status bar allowance
    float activityBarW = 42.0f;
    float sidebarW = 220.0f;
    float editorW = availW - activityBarW - sidebarW - 12.0f;

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.12f, 0.12f, 1.0f));
    ImGui::BeginChild("ActivityBar", ImVec2(activityBarW, availH), false);
    RenderActivityBar(app);
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::SameLine(0.0f, 4.0f);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.14f, 0.14f, 0.14f, 1.0f));
    ImGui::BeginChild("SidebarPane", ImVec2(sidebarW, availH), true);
    RenderSidebarPane(app);
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::SameLine(0.0f, 4.0f);

    float editorPaneH = showProblemsPanel_ ? (availH - 170.0f) : availH;
    ImGui::BeginChild("EditorPane", ImVec2(editorW, editorPaneH), true);
    RenderEditorPane(app);
    ImGui::EndChild();

    if (showProblemsPanel_)
    {
        ImGui::SetCursorPos(ImVec2(activityBarW + sidebarW + 12.0f, ImGui::GetWindowHeight() - 26.0f - 170.0f));
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.13f, 0.13f, 0.13f, 1.0f));
        ImGui::BeginChild("ProblemsPanel", ImVec2(editorW, 168.0f), true);
        RenderProblemsPanel(app);
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    // 4. Status Bar
    RenderStatusBar(app);

    RenderModals();

    ImGui::End();
}

void OpenReverseEditorPanel::RenderActivityBar(Application& app)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 actP = ImGui::GetCursorScreenPos();
    float activityBarW = 42.0f;

    auto drawFileIcon = [&](ImVec2 pos, ImU32 col) {
        float w = 13.f;
        float h = 16.f;
        float fold = 4.0f;

        dl->PathLineTo(ImVec2(pos.x, pos.y));
        dl->PathLineTo(ImVec2(pos.x + w - fold, pos.y));
        dl->PathLineTo(ImVec2(pos.x + w, pos.y + fold));
        dl->PathLineTo(ImVec2(pos.x + w, pos.y + h));
        dl->PathLineTo(ImVec2(pos.x, pos.y + h));
        dl->PathFillConvex(IM_COL32(30, 30, 30, 255));

        dl->PathLineTo(ImVec2(pos.x, pos.y));
        dl->PathLineTo(ImVec2(pos.x + w - fold, pos.y));
        dl->PathLineTo(ImVec2(pos.x + w, pos.y + fold));
        dl->PathLineTo(ImVec2(pos.x + w, pos.y + h));
        dl->PathLineTo(ImVec2(pos.x, pos.y + h));
        dl->PathStroke(col, ImDrawFlags_Closed, 1.8f);

        dl->AddLine(ImVec2(pos.x + w - fold, pos.y), ImVec2(pos.x + w - fold, pos.y + fold), col, 1.8f);
        dl->AddLine(ImVec2(pos.x + w - fold, pos.y + fold), ImVec2(pos.x + w, pos.y + fold), col, 1.8f);
    };

    // --- 1. EXPLORER ICON BUTTON ---
    ImGui::SetCursorScreenPos(ImVec2(actP.x, actP.y + 10.f));
    if (ImGui::InvisibleButton("##TabExplorer", ImVec2(activityBarW, 40.f)))
    {
        activeSidebarTab_ = 0;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Explorer (Files & Folders)");

    ImU32 colExp = (activeSidebarTab_ == 0) ? IM_COL32(255, 255, 255, 255) : IM_COL32(140, 140, 140, 255);
    drawFileIcon(ImVec2(actP.x + 10.f, actP.y + 18.f), IM_COL32(100, 100, 100, 255));
    drawFileIcon(ImVec2(actP.x + 15.f, actP.y + 23.f), colExp);

    if (activeSidebarTab_ == 0)
    {
        dl->AddRectFilled(ImVec2(actP.x, actP.y + 16.f), ImVec2(actP.x + 3.0f, actP.y + 44.f), IM_COL32(69, 162, 158, 255), 2.0f);
    }

    // --- 2. SEARCH & REPLACE ICON BUTTON ---
    ImGui::SetCursorScreenPos(ImVec2(actP.x, actP.y + 55.f));
    if (ImGui::InvisibleButton("##TabSearch", ImVec2(activityBarW, 40.f)))
    {
        activeSidebarTab_ = 1;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Search & Replace across Scripts");

    ImU32 colSearch = (activeSidebarTab_ == 1) ? IM_COL32(255, 255, 255, 255) : IM_COL32(140, 140, 140, 255);
    float cx = actP.x + 20.f;
    float cy = actP.y + 73.f;
    float r = 6.0f;
    dl->AddCircle(ImVec2(cx, cy), r, colSearch, 16, 2.0f);
    dl->AddLine(ImVec2(cx - r * 0.707f, cy + r * 0.707f), ImVec2(cx - r * 0.707f - 5.5f, cy + r * 0.707f + 5.5f), colSearch, 2.0f);

    if (activeSidebarTab_ == 1)
    {
        dl->AddRectFilled(ImVec2(actP.x, actP.y + 60.f), ImVec2(actP.x + 3.0f, actP.y + 88.f), IM_COL32(69, 162, 158, 255), 2.0f);
    }

    // --- 3. PROBLEMS CONSOLE ICON BUTTON ---
    ImGui::SetCursorScreenPos(ImVec2(actP.x, actP.y + 100.f));
    if (ImGui::InvisibleButton("##TabProblems", ImVec2(activityBarW, 40.f)))
    {
        showProblemsPanel_ = !showProblemsPanel_;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Toggle Problems & Syntax Console");

    ImU32 colProb = showProblemsPanel_ ? IM_COL32(255, 255, 255, 255) : IM_COL32(140, 140, 140, 255);
    float tx = actP.x + 11.f;
    float ty = actP.y + 112.f;
    dl->AddRect(ImVec2(tx, ty), ImVec2(tx + 20.f, ty + 16.f), colProb, 3.0f, 0, 1.8f);
    // Draw '>' prompt chevron inside terminal box
    dl->AddLine(ImVec2(tx + 4.f, ty + 4.f), ImVec2(tx + 8.f, ty + 8.f), colProb, 1.8f);
    dl->AddLine(ImVec2(tx + 8.f, ty + 8.f), ImVec2(tx + 4.f, ty + 12.f), colProb, 1.8f);
    // Draw '_' underscore cursor
    dl->AddLine(ImVec2(tx + 10.f, ty + 12.f), ImVec2(tx + 15.f, ty + 12.f), colProb, 1.8f);

    if (showProblemsPanel_)
    {
        dl->AddRectFilled(ImVec2(actP.x, actP.y + 104.f), ImVec2(actP.x + 3.0f, actP.y + 132.f), IM_COL32(0, 122, 204, 255), 2.0f);
    }
}

void OpenReverseEditorPanel::RenderSidebarPane(Application& app)
{
    if (activeSidebarTab_ == 0)
    {
        RenderExplorerTab(app);
    }
    else if (activeSidebarTab_ == 1)
    {
        RenderSearchTab(app);
    }
}

void OpenReverseEditorPanel::RenderExplorerTab(Application& app)
{
    ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.8f, 1.0f), "EXPLORER");
    ImGui::Separator();

    ImGui::InputTextWithHint("##Filter", "Filter scripts...", searchBuf_, sizeof(searchBuf_));
    ImGui::Separator();

    // Right-Click Context Menu on blank Explorer area (Paris-main style)
    if (ImGui::BeginPopupContextWindow("ExplorerBlankContext", ImGuiPopupFlags_MouseButtonRight | ImGuiPopupFlags_NoOpenOverItems))
    {
        if (ImGui::Selectable("  + New Script File"))
        {
            showNewFileModal_ = true;
        }
        if (ImGui::Selectable("  + New Folder"))
        {
            showNewFolderModal_ = true;
        }
        if (ImGui::Selectable("  Refresh Disk Directory"))
        {
            ScanWorkspaceFolder();
        }
        ImGui::EndPopup();
    }

    std::vector<std::string> categories;
    for (const auto& f : files_)
    {
        if (std::find(categories.begin(), categories.end(), f.category) == categories.end())
        {
            categories.push_back(f.category);
        }
    }

    for (const auto& cat : categories)
    {
        if (ImGui::TreeNodeEx(cat.c_str(), ImGuiTreeNodeFlags_DefaultOpen))
        {
            for (const auto& f : files_)
            {
                if (f.category != cat)
                    continue;

                if (searchBuf_[0] != '\0' && f.name.find(searchBuf_) == std::string::npos)
                    continue;

                bool isSelected = (currentSelectedPath_ == f.path);
                ImGuiTreeNodeFlags nodeFlags = ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen |
                                               (isSelected ? ImGuiTreeNodeFlags_Selected : 0);

                ImGui::TreeNodeEx(f.name.c_str(), nodeFlags);
                if (ImGui::IsItemClicked(0))
                {
                    OpenFileFromDisk(f.path);
                }

                // File Context Menu (Right-Click on file, Paris-main style)
                if (ImGui::BeginPopupContextItem(("FileCtx_" + f.path).c_str(), ImGuiPopupFlags_MouseButtonRight))
                {
                    if (ImGui::Selectable("  Rename File"))
                    {
                        showRenameModal_ = true;
                        renamePath_ = f.path;
                        strncpy_s(renameBuf_, f.name.c_str(), sizeof(renameBuf_));
                    }
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.35f, 0.35f, 1.0f));
                    if (ImGui::Selectable("  Delete File"))
                    {
                        DeleteFileFromDisk(f.path);
                    }
                    ImGui::PopStyleColor();
                    ImGui::EndPopup();
                }
            }
            ImGui::TreePop();
        }
    }
}

void OpenReverseEditorPanel::RenderSearchTab(Application& app)
{
    ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.8f, 1.0f), "SEARCH & REPLACE");
    ImGui::Separator();

    ImGui::Text("Search across workspace:");
    if (ImGui::InputTextWithHint("##SearchInput", "Search query...", searchQueryBuf_, sizeof(searchQueryBuf_), ImGuiInputTextFlags_EnterReturnsTrue))
    {
        PerformGlobalSearch();
    }
    ImGui::Text("Replace with:");
    ImGui::InputTextWithHint("##ReplaceInput", "Replacement...", replaceQueryBuf_, sizeof(replaceQueryBuf_));

    if (ImGui::Button("Search All Files", ImVec2(100, 0)))
    {
        PerformGlobalSearch();
    }
    ImGui::SameLine();
    if (ImGui::Button("Replace All", ImVec2(100, 0)))
    {
        PerformGlobalReplace();
    }
    ImGui::Separator();

    ImGui::TextDisabled("Matches found: %zu", searchResults_.size());
    ImGui::Separator();

    ImGui::BeginChild("SearchResultsList", ImVec2(0, 0), false);
    for (size_t i = 0; i < searchResults_.size(); ++i)
    {
        const auto& res = searchResults_[i];
        std::string label = res.filename + ":" + std::to_string(res.line) + " - " + res.matchingText;
        if (ImGui::Selectable(label.c_str()))
        {
            OpenFileFromDisk(res.filepath);
            textEditor_.SetCursorPosition(::TextEditor::Coordinates(res.line - 1, 0));
        }
    }
    ImGui::EndChild();
}

void OpenReverseEditorPanel::RenderEditorPane(Application& app)
{
    if (openTabs_.empty())
    {
        RenderWelcomeScreen(app);
        return;
    }

    if (activeTabIdx_ >= 0 && activeTabIdx_ < static_cast<int>(openTabs_.size()))
    {
        auto& activeTab = openTabs_[activeTabIdx_];
        activeTab.currentText = textEditor_.GetText();
        activeTab.isDirty = activeTab.currentText != activeTab.initialText;
    }

    if (ImGui::BeginTabBar("EditorFileTabs", ImGuiTabBarFlags_Reorderable | ImGuiTabBarFlags_AutoSelectNewTabs))
    {
        for (size_t i = 0; i < openTabs_.size(); ++i)
        {
            bool tabOpen = true;
            ImGuiTabItemFlags tabFlags = (activeTabIdx_ == (int)i) ? ImGuiTabItemFlags_SetSelected : 0;

            std::string label = (openTabs_[i].isDirty ? "* " : "") + openTabs_[i].filename + "###Tab_" + std::to_string(i);

            if (ImGui::BeginTabItem(label.c_str(), &tabOpen, tabFlags))
            {
                if (activeTabIdx_ != (int)i)
                {
                    activeTabIdx_ = (int)i;
                    textEditor_.SetText(openTabs_[i].currentText);
                    currentSelectedPath_ = openTabs_[i].filepath;
                }
                ImGui::EndTabItem();
            }

            if (!tabOpen)
            {
                if (openTabs_[i].isDirty)
                {
                    Logger::Get().Log(LogLevel::Warning, "Save changes before closing %s",
                                      openTabs_[i].filename.c_str());
                    break;
                }
                openTabs_.erase(openTabs_.begin() + i);
                if (activeTabIdx_ >= (int)openTabs_.size())
                {
                    activeTabIdx_ = (int)openTabs_.size() - 1;
                }
                if (activeTabIdx_ >= 0)
                {
                    textEditor_.SetText(openTabs_[activeTabIdx_].currentText);
                }
                break;
            }
        }
        ImGui::EndTabBar();
    }

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]);
    textEditor_.Render("OpenReverseTextEditor");
    ImGui::PopFont();
}

void OpenReverseEditorPanel::RenderWelcomeScreen(Application& app)
{
    float winW = ImGui::GetContentRegionAvail().x;
    float winH = ImGui::GetContentRegionAvail().y;

    ImGui::SetCursorPosY(winH * 0.28f);
    const char* t1 = "OpenReverse Studio Editor";
    ImGui::SetCursorPosX((winW - ImGui::CalcTextSize(t1).x) * 0.5f);
    ImGui::TextColored(ImVec4(1.0f, 1.0f, 1.0f, 1.0f), "%s", t1);

    ImGui::Dummy(ImVec2(0, 10.0f));
    const char* t2 = "Open a script from Explorer or create a new file to get started";
    ImGui::SetCursorPosX((winW - ImGui::CalcTextSize(t2).x) * 0.5f);
    ImGui::TextColored(ImVec4(0.55f, 0.55f, 0.55f, 1.0f), "%s", t2);

    ImGui::Dummy(ImVec2(0, 24.0f));
    const char* t3 = "Ctrl+S: Save File   |   Ctrl+F: Search & Replace";
    ImGui::SetCursorPosX((winW - ImGui::CalcTextSize(t3).x) * 0.5f);
    ImGui::TextDisabled("%s", t3);
}

void OpenReverseEditorPanel::RenderProblemsPanel(Application& app)
{
    ImGui::SetCursorPos(ImVec2(12.f, 4.f));
    ImGui::TextColored(ImVec4(0.85f, 0.85f, 0.85f, 1.f), "PROBLEMS");
    ImGui::GetWindowDrawList()->AddLine(
        ImVec2(ImGui::GetWindowPos().x + 10.f, ImGui::GetWindowPos().y + 22.f),
        ImVec2(ImGui::GetWindowPos().x + 80.f, ImGui::GetWindowPos().y + 22.f),
        IM_COL32(0, 122, 204, 255), 2.f);

    ImGui::SetCursorPos(ImVec2(12.f, 28.f));
    ImGui::BeginChild("ProblemsList", ImVec2(0, 0), false);
    ImGui::TextDisabled("Compiler diagnostics are not available in the draft editor.");
    ImGui::EndChild();
}

void OpenReverseEditorPanel::RenderStatusBar(Application& app)
{
    ImGui::SetCursorPos(ImVec2(0, ImGui::GetWindowHeight() - 24.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.08f, 0.08f, 0.08f, 1.0f));
    ImGui::BeginChild("StatusBar", ImVec2(ImGui::GetWindowWidth(), 24.0f), false);

    ImGui::SetCursorPos(ImVec2(10.f, 4.f));
    ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Draft editor");
    if (ImGui::IsItemClicked())
    {
        showProblemsPanel_ = !showProblemsPanel_;
    }

    ImGui::SameLine(ImGui::GetWindowWidth() - 360.0f);
    ImGui::TextDisabled("Editing only  |  UTF-8  |  v2.0");

    ImGui::EndChild();
    ImGui::PopStyleColor();
}

void OpenReverseEditorPanel::RenderTopActionBar(Application& app)
{
    ImGui::BeginDisabled();
    ImGui::Button("  Script execution unavailable  ");
    ImGui::EndDisabled();

    ImGui::SameLine(0.0f, 10.0f);
    if (ImGui::Button("  + New Script  "))
    {
        showNewFileModal_ = true;
    }

    ImGui::SameLine(0.0f, 10.0f);
    if (ImGui::Button("  + New Folder  "))
    {
        showNewFolderModal_ = true;
    }

    ImGui::SameLine(0.0f, 10.0f);
    if (ImGui::Button("  [s] Save (Ctrl+S)  "))
    {
        SaveActiveFileToDisk();
    }

    ImGui::SameLine(0.0f, 10.0f);
    if (ImGui::Button("  [C] Reload Disk  "))
    {
        ScanWorkspaceFolder();
        if (activeTabIdx_ >= 0 && activeTabIdx_ < (int)openTabs_.size())
        {
            OpenFileFromDisk(openTabs_[activeTabIdx_].filepath);
        }
        Logger::Get().Log(LogLevel::Info, "[OpenReverse Editor] Re-scanned workspace directory.");
    }

    ImGui::SameLine(0.0f, 10.0f);
    if (ImGui::Button(app.isEditorFloating ? "  v  Dock to IDE  " : "  ^  Pop Out  "))
    {
        app.isEditorFloating = !app.isEditorFloating;
        Logger::Get().Log(LogLevel::Info, "%s", app.isEditorFloating ? "[Editor] Opened as separate floating window." : "[Editor] Docked back into IDE.");
    }

    ImGui::SameLine(0.0f, 20.0f);
    ImGui::TextDisabled("|  Workspace: %s (%zu scripts)", workspaceDir_.c_str(), files_.size());

    ImGui::Separator();
}

void OpenReverseEditorPanel::RenderModals()
{
    if (showNewFileModal_)
    {
        ImGui::OpenPopup("Create New Script File");
    }
    if (ImGui::BeginPopupModal("Create New Script File", &showNewFileModal_, ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImGui::Text("Enter script filename (e.g. hook_patch.cpp, analyzer.py):");
        ImGui::InputText("Filename", newFilenameBuf_, sizeof(newFilenameBuf_));
        ImGui::InputText("Folder", newFolderBuf_, sizeof(newFolderBuf_));

        ImGui::Separator();
        if (ImGui::Button("Create Script", ImVec2(120, 0)))
        {
            CreateNewFileOnDisk(newFilenameBuf_, newFolderBuf_);
            showNewFileModal_ = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0)))
        {
            showNewFileModal_ = false;
        }
        ImGui::EndPopup();
    }

    if (showNewFolderModal_)
    {
        ImGui::OpenPopup("Create New Workspace Folder");
    }
    if (ImGui::BeginPopupModal("Create New Workspace Folder", &showNewFolderModal_, ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImGui::Text("Enter new folder name in workspace:");
        ImGui::InputText("Folder Name", newFolderBuf_, sizeof(newFolderBuf_));

        ImGui::Separator();
        if (ImGui::Button("Create Folder", ImVec2(120, 0)))
        {
            CreateNewFolderOnDisk(newFolderBuf_);
            showNewFolderModal_ = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0)))
        {
            showNewFolderModal_ = false;
        }
        ImGui::EndPopup();
    }

    if (showRenameModal_)
    {
        ImGui::OpenPopup("Rename Script File");
    }
    if (ImGui::BeginPopupModal("Rename Script File", &showRenameModal_, ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImGui::Text("Enter new filename:");
        ImGui::InputText("New Name", renameBuf_, sizeof(renameBuf_));

        ImGui::Separator();
        if (ImGui::Button("Rename", ImVec2(120, 0)))
        {
            RenameFileOnDisk(renamePath_, renameBuf_);
            showRenameModal_ = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0)))
        {
            showRenameModal_ = false;
        }
        ImGui::EndPopup();
    }
}

} // namespace openreverse
