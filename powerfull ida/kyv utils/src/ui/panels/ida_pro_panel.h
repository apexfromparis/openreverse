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
    const FunctionInfo& GetActiveFunction() const { return activeFunction_; }
    const std::string& GetActivePseudocode() const { return activePseudocode_; }

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
    void RenderScriptEditorTab(Application& app);

    // Dev Creator Studio (Script Editor & AI Assistant Tab)
    char                      scriptBuffer_[8192] =
        "// =========================================================================\n"
        "// ODNC OpenReverse Dev Creator Studio - Plugin Script Editor\n"
        "// Access loaded functions, memory & AI SDK in your custom heuristics\n"
        "// =========================================================================\n"
        "void OnAnalyzeModule(kyv::Application& app, std::vector<kyv::FunctionInfo>& funcs) {\n"
        "    // Example: Auto-tag suspicious cryptographic loops\n"
        "    for (auto& fn : funcs) {\n"
        "        if (fn.cyclomaticComplexity > 10 && fn.name.find(\"sub_\") == 0) {\n"
        "            fn.name = \"crypto_candidate_\" + helpers::FormatAddress(fn.startAddress, true);\n"
        "        }\n"
        "    }\n"
        "}\n";
    char                      devAiPrompt_[1024] = "";
    std::string               devAiResponse_ = "Welcome to ODNC Dev Creator Studio. Type a prompt below to ask AI for script heuristics!";
    std::string               scriptLog_ = "[*] ODNC Dev Creator Studio initialized. Ready to execute scripts against target binary.\n";
};

}} // namespace kyv::panels
