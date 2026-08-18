#pragma once

#include "workspace/cancellation.h"
#include "analysis/data_evidence.h"
#include "analysis/functions.h"
#include "targets/module_catalog.h"
#include "analysis/pe_parser.h"
#include "analysis/offset_model.h"
#include "analysis/string_scanner.h"
#include "analysis/xref_scanner.h"
#include "analysis/symbol_provider.h"

#include <chrono>
#include <functional>
#include <string>
#include <vector>

namespace openreverse {

struct ModuleAnalysisOptions {
    size_t maxCodeBytes = 128ULL * 1024ULL * 1024ULL;
    size_t maxStringBytes = 32ULL * 1024ULL * 1024ULL;
    size_t maxInstructions = 4000000;
    size_t maxCfgInstructions = 2000000;
    size_t maxInstructionsPerFunction = 4096;
    size_t maxFunctionBytes = 65536;
    size_t maxFunctions = 200000;
    size_t maxStrings = 100000;
    std::chrono::milliseconds maxDuration{120000};
};

struct ModuleAnalysisResult {
    bool success = false;
    bool cancelled = false;
    bool codeBudgetReached = false;
    bool stringBudgetReached = false;
    bool instructionBudgetReached = false;
    bool cfgInstructionBudgetReached = false;
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
    std::vector<SymbolRecord> symbols;
    std::vector<SymbolTypeRecord> symbolTypes;
    SymbolProviderIdentity symbolIdentity;
    bool symbolsLoaded = false;
    std::string symbolDiagnostic;
    size_t codeBytesAnalyzed = 0;
    size_t stringBytesAnalyzed = 0;
    size_t cfgFunctionsAnalyzed = 0;
    size_t cfgInstructionsAnalyzed = 0;
    std::chrono::milliseconds peDuration{0};
    std::chrono::milliseconds codeDuration{0};
    std::chrono::milliseconds cfgDuration{0};
    std::chrono::milliseconds dataDuration{0};
    std::chrono::milliseconds stringDuration{0};
    std::chrono::milliseconds signatureDuration{0};
    std::chrono::milliseconds totalDuration{0};
};

class ModuleAnalysisPipeline {
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
