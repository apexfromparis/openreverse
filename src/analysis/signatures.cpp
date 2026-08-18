#include "signatures.h"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>

namespace openreverse {

namespace {

bool AddSigned(uint64_t base, int64_t offset, uint64_t& result)
{
    if (offset >= 0)
    {
        const uint64_t value = static_cast<uint64_t>(offset);
        if (value > (std::numeric_limits<uint64_t>::max)() - base) return false;
        result = base + value;
        return true;
    }
    const uint64_t magnitude = static_cast<uint64_t>(-(offset + 1)) + 1;
    if (magnitude > base) return false;
    result = base - magnitude;
    return true;
}

void WildcardRange(std::vector<PatternByte>& pattern, size_t instructionStart,
                   uint8_t offset, uint8_t size)
{
    if (size == 0 || instructionStart + offset > pattern.size() ||
        size > pattern.size() - instructionStart - offset)
        return;
    for (size_t index = 0; index < size; ++index)
        pattern[instructionStart + offset + index].wildcard = true;
}

} // namespace

SignatureRecord signatures::Generate(const std::vector<Instruction>& instructions,
                                     size_t startIndex,
                                     const SignatureRelationship& relationship,
                                     const SignatureGenerationOptions& options)
{
    SignatureRecord record;
    record.relationship = relationship;
    if (startIndex >= instructions.size() || options.minimumBytes == 0 ||
        options.maximumBytes < options.minimumBytes)
        return record;

    const uint64_t startAddress = instructions[startIndex].address;
    uint64_t expectedAddress = startAddress;
    for (size_t index = startIndex; index < instructions.size(); ++index)
    {
        const auto& instruction = instructions[index];
        if (instruction.address != expectedAddress || instruction.size == 0 ||
            record.pattern.size() + instruction.size > options.maximumBytes)
            break;
        const size_t instructionStart = record.pattern.size();
        for (size_t byteIndex = 0; byteIndex < instruction.size; ++byteIndex)
            record.pattern.push_back({instruction.bytes[byteIndex], false});

        bool hasRipRelative = false;
        bool hasAbsolutePointer = false;
        for (const auto& operand : instruction.decodedOperands)
        {
            if (operand.type == OperandType::Memory && operand.memory.ripRelative)
                hasRipRelative = true;
            if (operand.type == OperandType::Immediate && options.imageSize != 0)
            {
                const uint64_t immediate = static_cast<uint64_t>(operand.immediate);
                hasAbsolutePointer = immediate >= options.imageBase &&
                    immediate - options.imageBase < options.imageSize;
            }
        }
        if (hasRipRelative)
            WildcardRange(record.pattern, instructionStart,
                          instruction.displacementOffset, instruction.displacementSize);
        if (relationship.kind == SignatureTargetKind::FieldDisplacement &&
            instruction.address - startAddress == relationship.instructionOffset)
        {
            const auto targetOperand = std::find_if(instruction.decodedOperands.begin(),
                instruction.decodedOperands.end(), [&](const DecodedOperand& operand) {
                    return operand.index == relationship.operandIndex &&
                           operand.type == OperandType::Memory;
                });
            if (targetOperand != instruction.decodedOperands.end())
                WildcardRange(record.pattern, instructionStart,
                              instruction.displacementOffset, instruction.displacementSize);
        }
        if ((instruction.isCall || instruction.isJump || hasAbsolutePointer) &&
            instruction.immediateSize != 0)
            WildcardRange(record.pattern, instructionStart,
                          instruction.immediateOffset, instruction.immediateSize);

        if (options.imageBase != 0 && instruction.address >= options.imageBase)
        {
            const uint64_t instructionRva = instruction.address - options.imageBase;
            for (uint32_t relocationRva : options.relocationRvas)
            {
                if (relocationRva >= instructionRva &&
                    relocationRva - instructionRva < instruction.size)
                    record.pattern[instructionStart + static_cast<size_t>(relocationRva - instructionRva)].wildcard = true;
            }
        }
        if (record.pattern.size() >= options.minimumBytes)
            break;
        expectedAddress = instruction.address + instruction.size;
    }

    if (record.pattern.size() < options.minimumBytes)
    {
        record.pattern.clear();
        return record;
    }
    record.targetFunction = startAddress;
    record.evidenceScore = static_cast<uint32_t>(record.pattern.size() -
        std::count_if(record.pattern.begin(), record.pattern.end(),
            [](const PatternByte& byte) { return byte.wildcard; }));
    record.status = SignatureStatus::NotFound;
    return record;
}

void signatures::Evaluate(SignatureRecord& signature,
                          const std::vector<uint8_t>& mappedImage,
                          const PEInfo& pe, size_t rawFileSize,
                          OfflinePatternScanScope scope)
{
    if (signature.pattern.empty() || !pe.valid)
    {
        signature.matchCount = 0;
        signature.status = SignatureStatus::Invalid;
        return;
    }
    OfflinePatternScanOptions options;
    options.scope = scope;
    options.patternIdentifier = signature.stableId;
    PatternScanner scanner;
    const auto report = scanner.ScanOffline(signature.pattern, mappedImage, pe, rawFileSize, options);
    signature.matchCount = report.results.size();
    signature.status = !report.error.empty() ? SignatureStatus::Invalid :
        signature.matchCount == 0 ? SignatureStatus::NotFound :
        signature.matchCount == 1 ? SignatureStatus::Unique : SignatureStatus::Ambiguous;
}

ResolvedSignatureTarget signatures::Resolve(
    const SignatureRecord& signature, uint64_t matchAddress,
    const std::vector<Instruction>& decodedAtMatch)
{
    ResolvedSignatureTarget result;
    result.kind = signature.relationship.kind;
    if (signature.relationship.kind == SignatureTargetKind::MatchAddress ||
        signature.relationship.kind == SignatureTargetKind::FunctionRva)
    {
        result.valid = AddSigned(matchAddress, signature.relationship.targetOffset, result.address);
        result.value = result.valid ? static_cast<int64_t>(result.address) : 0;
        return result;
    }

    uint64_t instructionAddress = 0;
    if (!AddSigned(matchAddress, signature.relationship.instructionOffset, instructionAddress))
        return result;
    const auto instruction = std::find_if(decodedAtMatch.begin(), decodedAtMatch.end(),
        [instructionAddress](const Instruction& value) { return value.address == instructionAddress; });
    if (instruction == decodedAtMatch.end())
        return result;
    const auto operand = std::find_if(instruction->decodedOperands.begin(), instruction->decodedOperands.end(),
        [&](const DecodedOperand& value) { return value.index == signature.relationship.operandIndex; });
    if (operand == instruction->decodedOperands.end() || operand->type != OperandType::Memory)
        return result;

    if (signature.relationship.kind == SignatureTargetKind::RipRelativeOperand &&
        operand->memory.ripRelative && operand->memory.resolved)
    {
        result.valid = AddSigned(operand->memory.resolvedAddress,
                                 signature.relationship.targetOffset, result.address);
        result.value = result.valid ? static_cast<int64_t>(result.address) : 0;
    }
    else if (signature.relationship.kind == SignatureTargetKind::FieldDisplacement &&
             !operand->memory.ripRelative)
    {
        result.valid = true;
        result.value = operand->memory.displacement + signature.relationship.targetOffset;
    }
    return result;
}

std::string signatures::FormatPattern(const std::vector<PatternByte>& pattern)
{
    std::ostringstream stream;
    stream << std::uppercase << std::hex << std::setfill('0');
    for (size_t index = 0; index < pattern.size(); ++index)
    {
        if (index != 0) stream << ' ';
        if (pattern[index].wildcard)
            stream << "??";
        else
            stream << std::setw(2) << static_cast<unsigned>(pattern[index].value);
    }
    return stream.str();
}

} // namespace openreverse
