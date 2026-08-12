#pragma once

#include "core/function_analyzer.h"

#include <cstdint>
#include <string>
#include <vector>

namespace openreverse {

struct FunctionFingerprint {
    uint64_t functionAddress = 0;
    std::vector<uint64_t> instructionTokens;
    std::vector<std::string> referencedStrings;
    size_t basicBlockCount = 0;
    size_t edgeCount = 0;
    size_t callCount = 0;
    size_t instructionCount = 0;
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
double CompareFunctionFingerprints(const FunctionFingerprint& oldFunction,
                                   const FunctionFingerprint& newFunction,
                                   std::vector<std::string>* evidence = nullptr);
std::vector<FunctionMigrationResult> CompareFunctionSets(
    const std::vector<FunctionFingerprint>& oldFunctions,
    const std::vector<FunctionFingerprint>& newFunctions,
    double minimumSimilarity = 0.45, double ambiguityMargin = 0.05);

} // namespace openreverse
