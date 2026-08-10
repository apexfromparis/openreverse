#pragma once
// ============================================================================
// OpenReverse - UI Panel: Function List, CFG, Experimental Pseudocode, and Xrefs
// ============================================================================

#include <cstdint>
#include <vector>
#include <string>
#include "core/function_analyzer.h"
#include "core/xref_scanner.h"
#include "core/pe_parser.h"
#include "core/disassembler.h"
#include "core/module_analyzer.h"

class TextEditor;

namespace openreverse {
class Application;

namespace panels {

class IDAProPanel {
public:
    IDAProPanel() = default;
    ~IDAProPanel();

    void Render(Application& app);
    void AnalyzeCurrentModule(Application& app);
    void StartAnalyzeCurrentModule(Application& app);
    void ResetAnalysis();
    void SetPEAnalysisResult(const std::vector<Instruction>& insns, const std::vector<PESectionInfo>& sections, const std::vector<PEImportEntry>& imports, const std::vector<PEInfo::PEExportEntry>& exports, bool is64Bit, const std::vector<FunctionInfo>& discoveredFuncs = {});
    void SelectFunction(Application& app, uint64_t funcAddress);
    void OpenXrefsForAddress(uint64_t address) { xrefTargetAddress_ = address; xrefModeTo_ = true; }
    const std::vector<FunctionInfo>& GetFunctions() const { return functions_; }
    const FunctionInfo& GetActiveFunction() const { return activeFunction_; }
    const std::string& GetActivePseudocode() const { return activePseudocode_; }

private:
    std::vector<FunctionInfo> functions_;
    FunctionInfo              activeFunction_;
    std::string               activePseudocode_;
    bool                      hasAnalyzed_ = false;
    uint64_t                  analysisJobId_ = 0;
    char                      filterText_[128] = {};

    // XREF Tab state
    uint64_t                  xrefTargetAddress_ = 0;
    char                      xrefAddressInput_[64] = "0";
    bool                      xrefModeTo_ = true; // true = To target, false = From source
    std::vector<XRefEntry>    currentXrefs_;

    void RenderFunctionsTab(Application& app);
    void RenderCFGTab(Application& app);
    void RenderDecompilerTab(Application& app);
    void RenderXRefsTab(Application& app);
    void RenderScriptEditorTab(Application& app);
    void ApplyModuleAnalysis(Application& app, ModuleAnalysisResult result);

    // Experimental script editor and AI assistant tab.
    char                      scriptBuffer_[8192] =
        "// =========================================================================\n"
        "// OpenReverse Experimental Analysis Script Draft\n"
        "// Script execution and plugin APIs are not implemented yet.\n"
        "// =========================================================================\n"
        "void OnAnalyzeModule(openreverse::Application& app, std::vector<openreverse::FunctionInfo>& funcs) {\n"
        "    // Example: Auto-tag suspicious cryptographic loops\n"
        "    for (auto& fn : funcs) {\n"
        "        if (fn.cyclomaticComplexity > 10 && fn.name.find(\"sub_\") == 0) {\n"
        "            fn.name = \"crypto_candidate_\" + helpers::FormatAddress(fn.startAddress, true);\n"
        "        }\n"
        "    }\n"
        "}\n";
    char                      devAiPrompt_[1024] = "";
    std::string               devAiResponse_ = "Ask the configured AI provider for help drafting analysis heuristics.";
    std::string               scriptLog_ = "[*] Editor preview initialized. Script execution and publishing are unavailable.\n";
    ::TextEditor*             textEditorPtr_ = nullptr;
};

}} // namespace openreverse::panels
