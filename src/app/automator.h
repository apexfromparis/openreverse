#pragma once

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
        size_t      analyzedSize = 0;
        int         complexity = 0;
        int         xrefCount = 0;
        std::string assemblySummary;
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
