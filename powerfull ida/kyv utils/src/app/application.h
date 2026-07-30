#pragma once
// ============================================================================
// KYV - Application
// Main application class that owns all core engines and UI panels
// ============================================================================

#include "core/process_manager.h"
#include "core/memory_reader.h"
#include "core/disassembler.h"
#include "core/pattern_scanner.h"
#include "core/module_manager.h"
#include "core/string_scanner.h"
#include "core/pe_parser.h"
#include "core/function_analyzer.h"
#include "core/xref_scanner.h"

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
#include "ui/panels/ida_pro_panel.h"

#include <string>
#include <memory>

namespace kyv {

class Application {
public:
    Application();
    ~Application();

    void Render();

    // ── Core Engines ──
    ProcessManager   processManager;
    MemoryReader     memoryReader;
    Disassembler     disassembler;
    PatternScanner   patternScanner;
    ModuleManager    moduleManager;
    StringScanner    stringScanner;
    PEParser         peParser;
    FunctionAnalyzer functionAnalyzer;
    XRefScanner      xrefScanner;
    ai::AIService    aiService;
    panels::IDAProPanel idaProPanel;

    // ── State ──
    bool             isAttached = false;
    DWORD            attachedPID = 0;
    HANDLE           processHandle = nullptr;
    std::string      attachedProcessName;
    bool             is64Bit = false;

    // ── Actions ──
    bool AttachToProcess(DWORD pid);
    void DetachFromProcess();
    void NavigateToAddress(uint64_t address);

    // ── Shared state for panels ──
    uint64_t         currentAddress = 0;
    std::vector<uint8_t> selectedBytes;

    void ShowGotoAddressDialog();
    void AddOffsetFromAddress(uint64_t address, const std::string& name = "");
    void ResetLayout() { layoutInitialized_ = false; }

private:
    // ── UI Panels ──
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

    bool             showGotoModal_ = false;
    char             gotoAddressBuf_[32] = "0";
    bool             layoutInitialized_ = false;

    void RenderMenuBar();
    void RenderStatusBar();
    void RenderDockspace();
};

} // namespace kyv
