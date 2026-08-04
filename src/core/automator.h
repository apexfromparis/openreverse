#pragma once
// ============================================================================
// OpenReverse - Core: Automator / Headless Engine
// Runs full analysis on a target process (Strings, CFG, Decompilation, XREFs)
// without GUI interaction and formats IDA Studio summary reports
// ============================================================================

#include "app/application.h"
#include <string>
#include <vector>
#include <cstdint>

namespace openreverse {

struct AutoAnalysisResult {
    bool         success = false;
    std::string  targetProcessName;
    DWORD        targetPid = 0;
    uint64_t     baseAddress = 0;
    size_t       functionsDiscovered = 0;
    size_t       totalXrefs = 0;
    size_t       stringsFound = 0;

    struct FunctionSummary {
        uint64_t    address = 0;
        std::string name;
        size_t      size = 0;
        int         complexity = 1;
        int         xrefCount = 0;
        std::string pseudocode;
    };

    std::vector<FunctionSummary> keyFunctions;
    std::vector<std::string>     c2Urls;
    std::vector<std::string>     registryKeys;
};

class Automator {
public:
    Automator() = default;
    ~Automator() = default;

    // Run automated IDA Pro / Hex-Rays analysis on a running process
    AutoAnalysisResult AnalyzeProcess(Application& app, DWORD pid, const std::string& processName = "");

    // Format the result into a beautiful markdown report
    static std::string FormatReport(const AutoAnalysisResult& res);
};

} // namespace openreverse
