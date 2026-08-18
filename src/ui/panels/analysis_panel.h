#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include "analysis/functions.h"
#include "analysis/xref_scanner.h"
#include "analysis/pe_parser.h"
#include "analysis/disassembler.h"
#include "analysis/module_analysis.h"

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
    void SelectFunction(Application& app, uint64_t funcAddress);
    void OpenXrefsForAddress(uint64_t address) { xrefTargetAddress_ = address; }
    void ApplyModuleAnalysis(Application& app, ModuleAnalysisResult result);
    const FunctionInfo& GetActiveFunction() const { return activeFunction_; }
    const std::string& GetActiveAssemblySummary() const { return activeAssemblySummary_; }

private:
    FunctionInfo              activeFunction_;
    std::string               activeAssemblySummary_;
    bool                      hasAnalyzed_ = false;
    uint64_t                  analysisJobId_ = 0;
    char                      filterText_[128] = {};

    uint64_t                  xrefTargetAddress_ = 0;
    uint64_t                  lastXrefSelection_ = 0;
    struct CFGGraphNode {
        uint64_t address = 0;
        size_t blockIndex = 0;
        float x = 0.0f;
        float y = 0.0f;
        float width = 0.0f;
        float height = 0.0f;
    };
    std::vector<CFGGraphNode> cfgGraphNodes_;
    uint64_t                  cfgGraphFunction_ = 0;
    size_t                    cfgGraphBlockCount_ = 0;
    float                     cfgGraphWidth_ = 0.0f;
    float                     cfgGraphHeight_ = 0.0f;
    float                     cfgGraphZoom_ = 1.0f;
    bool                      requestAnnotationPopup_ = false;
    uint64_t                  annotationRva_ = 0;
    char                      annotationName_[128] = {};
    char                      annotationComment_[512] = {};

    void RenderFunctionsTab(Application& app);
    void RenderAnnotationPopup(Application& app);
    void RenderCFGTab(Application& app);
    void RenderAssemblySummaryTab(Application& app);
    void RenderXRefsTab(Application& app);
    void RebuildCFGGraphLayout();
};

}} // namespace openreverse::panels
