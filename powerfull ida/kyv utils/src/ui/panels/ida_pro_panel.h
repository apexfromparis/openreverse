#pragma once
// ============================================================================
// KYV - UI Panel: IDA Pro Studio (Function List, CFG Basic Blocks, Hex-Rays Decompiler, XREFs)
// ============================================================================

#include <cstdint>
#include <vector>
#include <string>
#include "core/function_analyzer.h"
#include "core/xref_scanner.h"

namespace kyv {
class Application;

namespace panels {

class IDAProPanel {
public:
    IDAProPanel() = default;
    ~IDAProPanel() = default;

    void Render(Application& app);
    void AnalyzeCurrentModule(Application& app);
    void SelectFunction(Application& app, uint64_t funcAddress);
    void OpenXrefsForAddress(uint64_t address) { xrefTargetAddress_ = address; xrefModeTo_ = true; }
    const std::vector<FunctionInfo>& GetFunctions() const { return functions_; }

private:
    std::vector<FunctionInfo> functions_;
    FunctionInfo              activeFunction_;
    std::string               activePseudocode_;
    bool                      hasAnalyzed_ = false;
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
};

}} // namespace kyv::panels
