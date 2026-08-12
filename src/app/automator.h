#pragma once
// Coordinates bounded headless analysis through the shared application state.

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
    std::vector<std::string>     urls;
    std::vector<std::string>     registryPaths;
};

class Automator {
public:
    Automator() = default;
    ~Automator() = default;

    AutoAnalysisResult AnalyzeProcess(Application& app, DWORD pid, const std::string& processName = "");

    static std::string FormatReport(const AutoAnalysisResult& res);
};

} // namespace openreverse
