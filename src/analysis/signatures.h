#pragma once

#include "analysis/disassembler.h"
#include "analysis/pattern_scanner.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace openreverse {

enum class SignatureTargetKind {
    MatchAddress,
    FunctionRva,
    RipRelativeOperand,
    FieldDisplacement
};

enum class SignatureStatus {
    Unique,
    Ambiguous,
    NotFound,
    Invalid
};

struct SignatureRelationship {
    SignatureTargetKind kind = SignatureTargetKind::MatchAddress;
    uint32_t instructionOffset = 0;
    uint8_t operandIndex = 0;
    int64_t targetOffset = 0;
};

struct SignatureRecord {
    std::string stableId;
    std::vector<PatternByte> pattern;
    SignatureRelationship relationship;
    uint64_t targetFunction = 0;
    uint64_t targetOffset = 0;
    size_t matchCount = 0;
    std::string sourceVersion;
    uint32_t evidenceScore = 0;
    SignatureStatus status = SignatureStatus::Invalid;
};

struct SignatureGenerationOptions {
    size_t minimumBytes = 12;
    size_t maximumBytes = 48;
    uint64_t imageBase = 0;
    uint64_t imageSize = 0;
    std::vector<uint32_t> relocationRvas;
};

struct ResolvedSignatureTarget {
    bool valid = false;
    SignatureTargetKind kind = SignatureTargetKind::MatchAddress;
    uint64_t address = 0;
    int64_t value = 0;
};

namespace signatures {

SignatureRecord Generate(const std::vector<Instruction>& instructions, size_t startIndex,
                         const SignatureRelationship& relationship,
                         const SignatureGenerationOptions& options = {});
void Evaluate(SignatureRecord& signature, const std::vector<uint8_t>& mappedImage,
              const PEInfo& pe, size_t rawFileSize,
              OfflinePatternScanScope scope = OfflinePatternScanScope::ExecutableSections);
ResolvedSignatureTarget Resolve(const SignatureRecord& signature, uint64_t matchAddress,
                                const std::vector<Instruction>& decodedAtMatch);
std::string FormatPattern(const std::vector<PatternByte>& pattern);

} // namespace signatures

} // namespace openreverse
