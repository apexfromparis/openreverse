#pragma once

#include "targets/process_access.h"
#include "targets/memory_reader.h"
#include "analysis/disassembler.h"
#include "targets/module_catalog.h"
#include "analysis/string_scanner.h"
#include "analysis/pe_parser.h"
#include "analysis/functions.h"
#include "analysis/xref_scanner.h"
#include "workspace/analysis_scheduler.h"
#include "workspace/analysis_database.h"
#include "workspace/analysis_session.h"
#include "targets/dump_loader.h"
#include "analysis/module_analysis.h"
#include "extensions/extension_manager.h"


#include "ui/panels/process_list.h"
#include "ui/panels/hex_editor.h"
#include "ui/panels/disasm_view.h"
#include "ui/panels/memory_map.h"
#include "ui/panels/modules_panel.h"
#include "ui/panels/scanner_panel.h"
#include "ui/panels/strings_panel.h"
#include "ui/panels/data_inspector.h"
#include "ui/panels/pe_viewer.h"
#include "ui/panels/bookmarks_panel.h"
#include "ui/panels/console_panel.h"
#include "ui/panels/offsets_panel.h"
#include "ui/panels/ai_copilot.h"
#include "ui/panels/analysis_panel.h"
#include "ui/panels/openreverse_editor.h"
#include "ui/panels/version_intelligence_panel.h"

#include <string>
#include <memory>
#include <vector>

namespace openreverse {

enum class AnalysisTargetKind {
    None,
    PEFile,
    MappedDump,
    RawDump,
    MinidumpModule,
    LiveProcess
};

class Application {
public:
    Application();
    ~Application();
    void Shutdown();

    void Render();

    ProcessAccess   processAccess;
    MemoryReader     memoryReader;
    Disassembler     disassembler;
    ModuleCatalog    moduleCatalog;
    StringScanner    stringScanner;
    PEParser         peParser;
    XRefScanner      xrefScanner;
    AnalysisScheduler analysisScheduler;
    AnalysisSession  analysisSession;
    AnalysisDatabase& analysisDatabase;
    extensions::ExtensionManager extensionManager;
    ai::AIService    aiService;
    panels::AnalysisPanel analysisPanel;
    OpenReverseEditorPanel openReverseEditorPanel;
    bool showOpenReverseEditor = true;
    bool isDevMode = false;
    bool isEditorFloating = false;
    void SwitchToDevMode(bool enable);

    bool             isAttached = false;
    AnalysisTargetKind targetKind = AnalysisTargetKind::None;
    DWORD            attachedPID = 0;
    HANDLE           processHandle = nullptr;
    std::string      attachedProcessName;
    bool             is64Bit = false;
    uint64_t         targetGeneration = 0;
    uint64_t         offlineAnalysisJobId = 0;

    bool AttachToProcess(DWORD pid);
    void DetachFromProcess();
    bool OpenBinaryFile(const std::string& filePath);
    bool OpenDumpFile(const std::string& filePath, const DumpImportOptions& options = {});
    bool OpenProjectFile(const std::string& filePath);
    bool SaveProjectFile(bool saveAs = false);
    bool AnalyzeCurrentModuleSynchronously();
    void PublishModuleAnalysis(ModuleAnalysisResult result);
    const ModuleAnalysisState* CurrentAnalysis() const;
    void ShowOpenFileDialog();
    void ShowOpenDumpDialog();
    void ShowOpenProjectDialog();
    void RestoreProjectUiAfterAnalysis();
    void NotifyExtensionsSessionChanged();
    void NavigateToAddress(uint64_t address);

    std::string      loadedFilePath;
    std::vector<uint8_t> offlineFileBuffer;
    std::vector<uint8_t> offlineImageBuffer;
    PEInfo            offlinePEInfo;

    uint64_t         currentAddress = 0;
    std::vector<StringResult> stringResults;
    std::vector<uint8_t> selectedBytes;

    void ShowGotoAddressDialog();
    void AddOffsetFromAddress(uint64_t address, const std::string& name = "");
    void ShowAnalysisPanel() { showAnalysisPanel_ = true; }
    void ResetLayout() { layoutInitialized_ = false; }
    std::string GetAIContextSummary();

private:
    panels::ProcessListPanel    processListPanel;
    panels::HexEditorPanel      hexEditorPanel;
    panels::DisasmViewPanel     disasmViewPanel;
    panels::MemoryMapPanel      memoryMapPanel;
    panels::ModulesPanel        modulesPanel;
    panels::ScannerPanel        scannerPanel;
    panels::StringsPanel        stringsPanel;
    panels::DataInspectorPanel  dataInspectorPanel;
    panels::PEViewerPanel       peViewerPanel;
    panels::BookmarksPanel      bookmarksPanel;
    panels::ConsolePanel        consolePanel;
    panels::OffsetsPanel        offsetsPanel;
    panels::AICopilotPanel      aiCopilotPanel;
    panels::VersionIntelligencePanel versionIntelligencePanel;


    bool             showGotoModal_ = false;
    char             gotoAddressBuf_[32] = "0";
    bool             layoutInitialized_ = false;
    bool             shutdown_ = false;
    bool             showAnalysisPanel_ = false;
    bool             showMemoryMap_ = false;
    bool             showScanner_ = false;
    bool             showStrings_ = false;
    bool             showDataInspector_ = false;
    bool             showPEViewer_ = false;
    bool             showBookmarks_ = false;
    bool             showConsole_ = false;
    bool             showVersionIntelligence_ = false;
    bool             showExtensions_ = false;
    bool             showDumpImportModal_ = false;
    bool             requestDumpImportPopup_ = false;
    std::string      pendingDumpPath_;
    std::string      dumpImportError_;
    std::vector<DumpModuleMetadata> pendingDumpModules_;
    int              pendingDumpModuleIndex_ = 0;
    int              dumpArchitectureIndex_ = 1;
    char             dumpImageBaseBuf_[32] = "0x140000000";
    char             dumpModuleSizeBuf_[32] = "0";
    bool             openingProjectTarget_ = false;

    void RenderMenuBar();
    void RenderBrandBar();
    void RenderToolbar();
    void RenderStatusBar();
    void RenderDockspace();
    void RenderDumpImportDialog();
    void RenderExtensionPanels();
    void RenderExtensionsWindow();
    bool ShowProjectTargetDialog(std::string& filePath) const;
};

} // namespace openreverse
