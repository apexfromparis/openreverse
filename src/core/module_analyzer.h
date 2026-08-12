#pragma once

#include "core/cancellation.h"
#include "core/data_analyzer.h"
#include "core/function_analyzer.h"
#include "core/module_manager.h"
#include "core/pe_parser.h"
#include "core/offset_model.h"
#include "core/string_scanner.h"
#include "core/xref_scanner.h"

#include <chrono>
#include <functional>
#include <string>
#include <vector>

namespace openreverse {

struct ModuleAnalysisOptions {
    size_t maxCodeBytes = 8ULL * 1024ULL * 1024ULL;
    size_t maxStringBytes = 8ULL * 1024ULL * 1024ULL;
    size_t maxInstructions = 250000;
    size_t maxFunctions = 10000;
    size_t maxStrings = 5000;
    std::chrono::milliseconds maxDuration{10000};
};

struct ModuleAnalysisResult {
    bool success = false;
    bool cancelled = false;
    bool codeBudgetReached = false;
    bool stringBudgetReached = false;
    bool instructionBudgetReached = false;
    bool functionLimitReached = false;
    bool timeBudgetReached = false;
    std::string error;
    ModuleInfo module{};
    PEInfo pe;
    std::vector<FunctionInfo> functions;
    std::vector<XRefEntry> xrefs;
    std::vector<StringResult> strings;
    std::vector<GlobalCandidate> globals;
    std::vector<FieldAccessCandidate> fieldAccesses;
    std::vector<StructureCandidate> structures;
    std::vector<OffsetRecord> offsets;
    std::vector<SignatureRecord> signatures;
    ModuleIdentity identity;
    size_t codeBytesAnalyzed = 0;
    size_t stringBytesAnalyzed = 0;
    std::chrono::milliseconds peDuration{0};
    std::chrono::milliseconds codeDuration{0};
    std::chrono::milliseconds stringDuration{0};
    std::chrono::milliseconds totalDuration{0};
};

class ModuleAnalyzer {
public:
    using ProgressCallback = std::function<void(float)>;

    ModuleAnalysisResult AnalyzeLive(HANDLE processHandle, const ModuleInfo& module, bool is64Bit,
                                     const ModuleAnalysisOptions& options = {},
                                     const CancellationToken* cancellation = nullptr,
                                     const ProgressCallback& progress = {}) const;
    ModuleAnalysisResult AnalyzeMappedImage(const std::vector<uint8_t>& mappedImage,
                                            size_t sourceFileSize,
                                            const ModuleInfo& module, const PEInfo& pe,
                                            const ModuleAnalysisOptions& options = {},
                                            const CancellationToken* cancellation = nullptr,
                                            const ProgressCallback& progress = {}) const;
};

} // namespace openreverse
