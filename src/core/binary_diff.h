#pragma once

#include "core/function_analyzer.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace openreverse {

struct FunctionFieldFingerprint {
    uint8_t argumentIndex = 0;
    int64_t displacement = 0;
    uint8_t width = 0;
    uint8_t access = 0;
    uint64_t instructionRole = 0;
};

struct FunctionFingerprintContext {
    uint64_t imageBase = 0;
    uint64_t imageSize = 0;
    std::vector<std::string> referencedStrings;
    std::vector<std::string> referencedImports;
    std::vector<std::string> referencedGlobals;
    std::vector<std::string> signatureFragments;
    std::vector<std::string> symbolNames;
    std::vector<FunctionFieldFingerprint> fields;
};

struct FunctionFingerprint {
    uint64_t functionAddress = 0;
    uint64_t functionRva = 0;
    std::vector<uint64_t> instructionTokens;
    std::vector<uint64_t> orderedInstructionNgrams;
    std::vector<uint64_t> basicBlockTokens;
    std::vector<uint64_t> orderedBlockNgrams;
    std::vector<uint64_t> cfgNeighborhoodTokens;
    std::vector<std::string> referencedStrings;
    std::vector<std::string> referencedImports;
    std::vector<std::string> referencedGlobals;
    std::vector<std::string> signatureFragments;
    std::vector<std::string> symbolNames;
    std::vector<FunctionFieldFingerprint> fields;
    std::vector<uint64_t> callTargets;
    std::array<size_t, 5> edgeTypeCounts{};
    size_t authoritativeSize = 0;
    size_t basicBlockCount = 0;
    size_t edgeCount = 0;
    size_t callCount = 0;
    size_t instructionCount = 0;
    uint64_t normalizedHash = 0;
    uint64_t cfgHash = 0;
    bool boundaryKnown = false;
    bool exported = false;
};

struct FunctionSimilarityBreakdown {
    double normalizedInstructions = 0.0;
    double orderedInstructions = 0.0;
    double basicBlocks = 0.0;
    double orderedBlocks = 0.0;
    double cfgNeighborhood = 0.0;
    double strings = 0.0;
    double imports = 0.0;
    double globals = 0.0;
    double signatures = 0.0;
    double symbols = 0.0;
    double cfg = 0.0;
    double calls = 0.0;
    double size = 0.0;
    double total = 0.0;
    bool exactNormalized = false;
};

struct FunctionMatchCandidate {
    uint64_t oldAddress = 0;
    uint64_t newAddress = 0;
    double similarityScore = 0.0;
    std::vector<std::string> evidence;
};

enum class MigrationStatus {
    NoMatch,
    UniqueCandidate,
    Ambiguous
};

struct FunctionMigrationResult {
    uint64_t oldAddress = 0;
    MigrationStatus status = MigrationStatus::NoMatch;
    std::vector<FunctionMatchCandidate> candidates;
};

FunctionFingerprint BuildFunctionFingerprint(const FunctionInfo& function,
                                             const std::vector<std::string>& referencedStrings = {});
FunctionFingerprint BuildFunctionFingerprint(const FunctionInfo& function,
                                             const FunctionFingerprintContext& context);
FunctionSimilarityBreakdown EvaluateFunctionFingerprints(
    const FunctionFingerprint& oldFunction, const FunctionFingerprint& newFunction);
double CompareFunctionFingerprints(const FunctionFingerprint& oldFunction,
                                   const FunctionFingerprint& newFunction,
                                   std::vector<std::string>* evidence = nullptr);
std::vector<FunctionMigrationResult> CompareFunctionSets(
    const std::vector<FunctionFingerprint>& oldFunctions,
    const std::vector<FunctionFingerprint>& newFunctions,
    double minimumSimilarity = 0.45, double ambiguityMargin = 0.05);

} // namespace openreverse
