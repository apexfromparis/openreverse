#pragma once
// OpenReverse - UI Panel: Function List, CFG, Experimental Pseudocode, and Xrefs

#include <cstdint>
#include <vector>
#include <string>
#include "core/function_analyzer.h"
#include "core/xref_scanner.h"
#include "core/pe_parser.h"
#include "core/disassembler.h"
#include "core/module_analyzer.h"

namespace openreverse {
class Application;

namespace panels {

class AnalysisPanel {
public:
    AnalysisPanel() = default;
    ~AnalysisPanel() = default;

    void Render(Application& app);
    void RenderXRefsPanel(Application& app);
    void AnalyzeCurrentModule(Application& app);
    void StartAnalyzeCurrentModule(Application& app);
    void ResetAnalysis();
    void SetPEAnalysisResult(const std::vector<Instruction>& insns, const std::vector<PESectionInfo>& sections, const std::vector<PEImportEntry>& imports, const std::vector<PEInfo::PEExportEntry>& exports, bool is64Bit, const std::vector<FunctionInfo>& discoveredFuncs = {});
    void SelectFunction(Application& app, uint64_t funcAddress);
    void OpenXrefsForAddress(uint64_t address) { xrefTargetAddress_ = address; }
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

    uint64_t                  xrefTargetAddress_ = 0;
    uint64_t                  lastXrefSelection_ = 0;

    void RenderFunctionsTab(Application& app);
    void RenderCFGTab(Application& app);
    void RenderDecompilerTab(Application& app);
    void RenderXRefsTab(Application& app);
    void ApplyModuleAnalysis(Application& app, ModuleAnalysisResult result);
};

}} // namespace openreverse::panels
