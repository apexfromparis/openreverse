#include "binary_diff.h"

#include <algorithm>
#include <cmath>
#include <set>

namespace openreverse {

namespace {

uint64_t OperandClassToken(const Instruction& instruction)
{
    uint64_t token = instruction.instructionId;
    for (const auto& operand : instruction.decodedOperands)
    {
        token = token * 1315423911ULL + static_cast<uint64_t>(operand.type) * 17ULL + operand.size;
        if (operand.type == OperandType::Memory)
        {
            token = token * 33ULL + (operand.memory.ripRelative ? 1ULL : 0ULL);
            token = token * 33ULL + (operand.memory.indexRegister.empty() ? 0ULL : 1ULL);
            token = token * 33ULL + operand.memory.scale;
        }
    }
    return token;
}

double CountSimilarity(size_t left, size_t right)
{
    if (left == 0 && right == 0) return 1.0;
    const size_t maximum = std::max(left, right);
    return maximum == 0 ? 1.0 : 1.0 - static_cast<double>(maximum - std::min(left, right)) / maximum;
}

template<typename T>
double MultisetSimilarity(std::vector<T> left, std::vector<T> right)
{
    if (left.empty() && right.empty()) return 1.0;
    std::sort(left.begin(), left.end());
    std::sort(right.begin(), right.end());
    size_t common = 0;
    size_t leftIndex = 0;
    size_t rightIndex = 0;
    while (leftIndex < left.size() && rightIndex < right.size())
    {
        if (left[leftIndex] == right[rightIndex])
        {
            ++common;
            ++leftIndex;
            ++rightIndex;
        }
        else if (left[leftIndex] < right[rightIndex])
            ++leftIndex;
        else
            ++rightIndex;
    }
    const size_t total = left.size() + right.size() - common;
    return total == 0 ? 1.0 : static_cast<double>(common) / total;
}

} // namespace

FunctionFingerprint BuildFunctionFingerprint(const FunctionInfo& function,
                                             const std::vector<std::string>& referencedStrings)
{
    FunctionFingerprint fingerprint;
    fingerprint.functionAddress = function.startAddress;
    fingerprint.basicBlockCount = function.cfg.basicBlocks.size();
    fingerprint.edgeCount = function.cfg.edges.size();
    fingerprint.callCount = function.callTargets.size();
    fingerprint.referencedStrings = referencedStrings;
    for (const auto& block : function.cfg.basicBlocks)
    {
        for (const auto& instruction : block.instructions)
        {
            fingerprint.instructionTokens.push_back(OperandClassToken(instruction));
            ++fingerprint.instructionCount;
        }
    }
    return fingerprint;
}

double CompareFunctionFingerprints(const FunctionFingerprint& oldFunction,
                                   const FunctionFingerprint& newFunction,
                                   std::vector<std::string>* evidence)
{
    const double instructions = MultisetSimilarity(oldFunction.instructionTokens,
                                                   newFunction.instructionTokens);
    const double strings = MultisetSimilarity(oldFunction.referencedStrings,
                                              newFunction.referencedStrings);
    const double blocks = CountSimilarity(oldFunction.basicBlockCount, newFunction.basicBlockCount);
    const double edges = CountSimilarity(oldFunction.edgeCount, newFunction.edgeCount);
    const double calls = CountSimilarity(oldFunction.callCount, newFunction.callCount);
    const double size = CountSimilarity(oldFunction.instructionCount, newFunction.instructionCount);
    const double score = instructions * 0.50 + strings * 0.15 + blocks * 0.10 +
        edges * 0.10 + calls * 0.05 + size * 0.10;

    if (evidence)
    {
        evidence->clear();
        if (instructions >= 0.8) evidence->push_back("normalized instructions closely match");
        if (strings >= 0.8 && (!oldFunction.referencedStrings.empty() ||
                              !newFunction.referencedStrings.empty()))
            evidence->push_back("referenced strings match");
        if (blocks == 1.0 && edges == 1.0) evidence->push_back("CFG shape matches");
        if (calls == 1.0) evidence->push_back("call count matches");
        if (size == 1.0) evidence->push_back("instruction count matches");
    }
    return score;
}

std::vector<FunctionMigrationResult> CompareFunctionSets(
    const std::vector<FunctionFingerprint>& oldFunctions,
    const std::vector<FunctionFingerprint>& newFunctions,
    double minimumSimilarity, double ambiguityMargin)
{
    std::vector<FunctionMigrationResult> results;
    minimumSimilarity = std::clamp(minimumSimilarity, 0.0, 1.0);
    ambiguityMargin = std::clamp(ambiguityMargin, 0.0, 1.0);
    for (const auto& oldFunction : oldFunctions)
    {
        FunctionMigrationResult result;
        result.oldAddress = oldFunction.functionAddress;
        for (const auto& newFunction : newFunctions)
        {
            FunctionMatchCandidate candidate;
            candidate.oldAddress = oldFunction.functionAddress;
            candidate.newAddress = newFunction.functionAddress;
            candidate.similarityScore = CompareFunctionFingerprints(
                oldFunction, newFunction, &candidate.evidence);
            if (candidate.similarityScore >= minimumSimilarity)
                result.candidates.push_back(std::move(candidate));
        }
        std::sort(result.candidates.begin(), result.candidates.end(),
            [](const auto& left, const auto& right) {
                if (left.similarityScore != right.similarityScore)
                    return left.similarityScore > right.similarityScore;
                return left.newAddress < right.newAddress;
            });
        if (result.candidates.empty())
            result.status = MigrationStatus::NoMatch;
        else if (result.candidates.size() > 1 &&
                 result.candidates[0].similarityScore - result.candidates[1].similarityScore <= ambiguityMargin)
            result.status = MigrationStatus::Ambiguous;
        else
            result.status = MigrationStatus::UniqueCandidate;
        results.push_back(std::move(result));
    }
    return results;
}

} // namespace openreverse
