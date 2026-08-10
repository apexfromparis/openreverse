#pragma once
#include "TextEditor.h"
#include <string>
#include <vector>
#include <filesystem>

namespace openreverse {
class Application;

struct EditorFileNode {
    std::string name;
    std::string path; // Absolute or relative path on disk
    std::string category; // Folder name or category
    bool isDirectory = false;
};

struct EditorTab {
    std::string filepath;
    std::string filename;
    std::string initialText;
    std::string currentText;
    bool isDirty = false;
};

struct SearchResult {
    std::string filepath;
    std::string filename;
    int line;
    std::string matchingText;
};

class OpenReverseEditorPanel {
public:
    OpenReverseEditorPanel();
    ~OpenReverseEditorPanel();

    void Render(Application& app, bool& p_open);
    void OpenFileFromDisk(const std::string& filepath);
    void SaveActiveFileToDisk();
    void CreateNewFileOnDisk(const std::string& filename, const std::string& folderName);
    void CreateNewFolderOnDisk(const std::string& folderName);
    void DeleteFileFromDisk(const std::string& filepath);
    void RenameFileOnDisk(const std::string& oldPath, const std::string& newName);
    void ScanWorkspaceFolder();
    void EnsureDefaultFiles();
    void PerformGlobalSearch();
    void PerformGlobalReplace();

    void SetWorkspaceDir(const std::string& dir) { workspaceDir_ = dir; }
    std::string GetWorkspaceDir() const { return workspaceDir_; }

private:
    ::TextEditor textEditor_;
    std::string workspaceDir_;
    std::vector<EditorFileNode> files_;
    std::vector<EditorTab> openTabs_;
    int activeTabIdx_ = -1;
    bool initialized_ = false;

    // Paris-main / VS Code state
    int activeSidebarTab_ = 0; // 0 = Explorer, 1 = Search
    bool showProblemsPanel_ = false;

    // Search & Replace
    char searchBuf_[128] = {};
    char searchQueryBuf_[256] = "";
    char replaceQueryBuf_[256] = "";
    std::vector<SearchResult> searchResults_;

    // Modals & Context Menus
    char newFilenameBuf_[128] = "new_script.cpp";
    char newFolderBuf_[128] = "user_scripts";
    char renameBuf_[128] = "";
    std::string renamePath_;
    bool showNewFileModal_ = false;
    bool showNewFolderModal_ = false;
    bool showRenameModal_ = false;
    std::string currentSelectedPath_;

    void RenderActivityBar(Application& app);
    void RenderSidebarPane(Application& app);
    void RenderExplorerTab(Application& app);
    void RenderSearchTab(Application& app);
    void RenderEditorPane(Application& app);
    void RenderWelcomeScreen(Application& app);
    void RenderProblemsPanel(Application& app);
    void RenderStatusBar(Application& app);
    void RenderTopActionBar(Application& app);
    void RenderModals();
};

} // namespace openreverse
