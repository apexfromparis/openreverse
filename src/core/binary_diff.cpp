#include "binary_diff.h"

#include <algorithm>
#include <cmath>
#include <cctype>

namespace openreverse {

namespace {

constexpr uint64_t kFnvOffset = 1469598103934665603ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

uint64_t HashValue(uint64_t hash, uint64_t value)
{
    for (unsigned byte = 0; byte < 8; ++byte)
    {
        hash ^= (value >> (byte * 8)) & 0xFF;
        hash *= kFnvPrime;
    }
    return hash;
}

bool IsStackRegister(const std::string& name)
{
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return lower == "rsp" || lower == "esp" || lower == "sp" ||
           lower == "rbp" || lower == "ebp" || lower == "bp";
}

uint64_t SignedClass(int64_t value)
{
    if (value >= -128 && value <= 255)
        return 0x100000000ULL | static_cast<uint64_t>(value + 128);
    const uint64_t magnitude = value < 0
        ? static_cast<uint64_t>(-(value + 1)) + 1 : static_cast<uint64_t>(value);
    if (magnitude != 0 && (magnitude & (magnitude - 1)) == 0)
        return 0x200000000ULL | static_cast<uint64_t>(std::min<unsigned>(63,
            static_cast<unsigned>(std::log2(static_cast<double>(magnitude)))));
    return 0x300000000ULL | (value < 0 ? 1ULL : 0ULL);
}

uint64_t OperandClassToken(const Instruction& instruction,
                           const FunctionFingerprintContext& context)
{
    uint64_t token = HashValue(kFnvOffset, instruction.instructionId);
    for (const auto& operand : instruction.decodedOperands)
    {
        token = HashValue(token, static_cast<uint64_t>(operand.type));
        token = HashValue(token, operand.size);
        token = HashValue(token, (operand.read ? 1ULL : 0ULL) | (operand.write ? 2ULL : 0ULL));
        if (operand.type == OperandType::Immediate)
        {
            const uint64_t immediate = static_cast<uint64_t>(operand.immediate);
            const bool relativeControlFlow = instruction.isCall || instruction.isJump;
            const bool addressLike = context.imageSize != 0 && immediate >= context.imageBase &&
                immediate - context.imageBase < context.imageSize;
            token = HashValue(token, relativeControlFlow ? 0xC001ULL :
                addressLike ? 0xA661ULL : SignedClass(operand.immediate));
        }
        else if (operand.type == OperandType::Memory)
        {
            const auto& memory = operand.memory;
            token = HashValue(token, memory.ripRelative ? 0x715ULL : 0x314ULL);
            token = HashValue(token, memory.indexRegister.empty() ? 0ULL : 1ULL);
            token = HashValue(token, memory.scale);
            token = HashValue(token, IsStackRegister(memory.baseRegister) ?
                SignedClass(memory.displacement) : 0xF13DULL);
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

uint64_t BuildCfgHash(const FunctionInfo& function)
{
    uint64_t hash = kFnvOffset;
    hash = HashValue(hash, function.cfg.basicBlocks.size());
    std::array<size_t, 5> counts{};
    for (const auto& edge : function.cfg.edges)
        ++counts[static_cast<size_t>(edge.type)];
    for (size_t count : counts) hash = HashValue(hash, count);
    std::vector<size_t> degrees;
    degrees.reserve(function.cfg.basicBlocks.size());
    for (const auto& block : function.cfg.basicBlocks)
        degrees.push_back((block.predecessors.size() << 16) | block.successors.size());
    std::sort(degrees.begin(), degrees.end());
    for (size_t degree : degrees) hash = HashValue(hash, degree);
    return hash;
}

} // namespace

FunctionFingerprint BuildFunctionFingerprint(const FunctionInfo& function,
                                             const std::vector<std::string>& referencedStrings)
{
    FunctionFingerprintContext context;
    context.referencedStrings = referencedStrings;
    return BuildFunctionFingerprint(function, context);
}

FunctionFingerprint BuildFunctionFingerprint(const FunctionInfo& function,
                                             const FunctionFingerprintContext& context)
{
    FunctionFingerprint fingerprint;
    fingerprint.functionAddress = function.startAddress;
    fingerprint.functionRva = context.imageBase != 0 && function.startAddress >= context.imageBase
        ? function.startAddress - context.imageBase : function.startAddress;
    fingerprint.authoritativeSize = function.boundaryKnown ? function.size : 0;
    fingerprint.basicBlockCount = function.cfg.basicBlocks.size();
    fingerprint.edgeCount = function.cfg.edges.size();
    fingerprint.callCount = function.callTargets.size();
    fingerprint.callTargets = function.callTargets;
    fingerprint.referencedStrings = context.referencedStrings;
    fingerprint.referencedImports = context.referencedImports;
    fingerprint.referencedGlobals = context.referencedGlobals;
    fingerprint.signatureFragments = context.signatureFragments;
    fingerprint.fields = context.fields;
    fingerprint.boundaryKnown = function.boundaryKnown;
    fingerprint.exported = function.isExported;
    fingerprint.cfgHash = BuildCfgHash(function);
    for (const auto& edge : function.cfg.edges)
        ++fingerprint.edgeTypeCounts[static_cast<size_t>(edge.type)];
    fingerprint.normalizedHash = kFnvOffset;
    for (const auto& block : function.cfg.basicBlocks)
    {
        for (const auto& instruction : block.instructions)
        {
            const uint64_t token = OperandClassToken(instruction, context);
            fingerprint.instructionTokens.push_back(token);
            fingerprint.normalizedHash = HashValue(fingerprint.normalizedHash, token);
            ++fingerprint.instructionCount;
        }
    }
    fingerprint.normalizedHash = HashValue(fingerprint.normalizedHash, fingerprint.instructionCount);
    return fingerprint;
}

FunctionSimilarityBreakdown EvaluateFunctionFingerprints(
    const FunctionFingerprint& oldFunction, const FunctionFingerprint& newFunction)
{
    FunctionSimilarityBreakdown result;
    result.normalizedInstructions = MultisetSimilarity(oldFunction.instructionTokens,
                                                        newFunction.instructionTokens);
    result.strings = MultisetSimilarity(oldFunction.referencedStrings,
                                        newFunction.referencedStrings);
    result.imports = MultisetSimilarity(oldFunction.referencedImports,
                                        newFunction.referencedImports);
    result.globals = MultisetSimilarity(oldFunction.referencedGlobals,
                                        newFunction.referencedGlobals);
    result.signatures = MultisetSimilarity(oldFunction.signatureFragments,
                                           newFunction.signatureFragments);
    const double blocks = CountSimilarity(oldFunction.basicBlockCount, newFunction.basicBlockCount);
    const double edges = CountSimilarity(oldFunction.edgeCount, newFunction.edgeCount);
    const double edgeKinds = MultisetSimilarity(
        std::vector<size_t>(oldFunction.edgeTypeCounts.begin(), oldFunction.edgeTypeCounts.end()),
        std::vector<size_t>(newFunction.edgeTypeCounts.begin(), newFunction.edgeTypeCounts.end()));
    result.cfg = blocks * 0.4 + edges * 0.3 + edgeKinds * 0.3;
    result.calls = CountSimilarity(oldFunction.callCount, newFunction.callCount);
    result.size = CountSimilarity(oldFunction.instructionCount, newFunction.instructionCount);
    result.exactNormalized = oldFunction.instructionCount != 0 &&
        oldFunction.normalizedHash == newFunction.normalizedHash &&
        oldFunction.instructionTokens == newFunction.instructionTokens;

    const bool hasStrings = !oldFunction.referencedStrings.empty() || !newFunction.referencedStrings.empty();
    const bool hasImports = !oldFunction.referencedImports.empty() || !newFunction.referencedImports.empty();
    const bool hasGlobals = !oldFunction.referencedGlobals.empty() || !newFunction.referencedGlobals.empty();
    const bool hasSignatures = !oldFunction.signatureFragments.empty() || !newFunction.signatureFragments.empty();
    double totalWeight = 0.80;
    result.total = result.normalizedInstructions * 0.52 + result.cfg * 0.14 +
        result.calls * 0.07 + result.size * 0.07;
    if (hasStrings) { result.total += result.strings * 0.08; totalWeight += 0.08; }
    if (hasImports) { result.total += result.imports * 0.05; totalWeight += 0.05; }
    if (hasGlobals) { result.total += result.globals * 0.04; totalWeight += 0.04; }
    if (hasSignatures) { result.total += result.signatures * 0.03; totalWeight += 0.03; }
    result.total = totalWeight == 0.0 ? 0.0 : result.total / totalWeight;
    return result;
}

double CompareFunctionFingerprints(const FunctionFingerprint& oldFunction,
                                   const FunctionFingerprint& newFunction,
                                   std::vector<std::string>* evidence)
{
    const auto result = EvaluateFunctionFingerprints(oldFunction, newFunction);
    if (evidence)
    {
        evidence->clear();
        if (result.exactNormalized) evidence->push_back("normalized instruction sequence is identical");
        else if (result.normalizedInstructions >= 0.8) evidence->push_back("normalized instructions closely match");
        if (result.strings >= 0.8 && (!oldFunction.referencedStrings.empty() ||
                                     !newFunction.referencedStrings.empty()))
            evidence->push_back("referenced strings match");
        if (result.imports >= 0.8 && (!oldFunction.referencedImports.empty() ||
                                     !newFunction.referencedImports.empty()))
            evidence->push_back("referenced imports match");
        if (result.cfg >= 0.95) evidence->push_back("CFG shape matches");
        if (result.calls == 1.0) evidence->push_back("call count matches");
        if (result.size == 1.0) evidence->push_back("instruction count matches");
    }
    return result.total;
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
