#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace openreverse {

class Application;

struct LiveAnalysisReport {
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

class LiveAnalysisReporter {
public:
    LiveAnalysisReport BuildForProcess(Application& app, DWORD pid,
                                       const std::string& processName = "") const;
    static std::string FormatMarkdown(const LiveAnalysisReport& report);
};

} // namespace openreverse
