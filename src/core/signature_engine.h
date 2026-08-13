#pragma once

#include "core/disassembler.h"
#include "core/pattern_scanner.h"

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
    size_t maximumBytes = 128;
    size_t minimumFixedBytes = 8;
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

class SignatureEngine {
public:
    SignatureRecord Generate(const std::vector<Instruction>& instructions, size_t startIndex,
                             const SignatureRelationship& relationship,
                             const SignatureGenerationOptions& options = {}) const;
    void Evaluate(SignatureRecord& signature, const std::vector<uint8_t>& mappedImage,
                  const PEInfo& pe, size_t rawFileSize,
                  OfflinePatternScanScope scope = OfflinePatternScanScope::ExecutableSections) const;
    ResolvedSignatureTarget Resolve(const SignatureRecord& signature, uint64_t matchAddress,
                                    const std::vector<Instruction>& decodedAtMatch) const;

    static std::string FormatPattern(const std::vector<PatternByte>& pattern);
};

} // namespace openreverse
