#include "offset_model.h"

#include <bcrypt.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>

namespace openreverse {

namespace {

using json = nlohmann::json;

std::string Hex(uint64_t value)
{
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << value;
    return stream.str();
}

bool ParseUnsigned(const json& value, uint64_t& result)
{
    try
    {
        if (value.is_number_unsigned())
        {
            result = value.get<uint64_t>();
            return true;
        }
        if (!value.is_string()) return false;
        const std::string text = value.get<std::string>();
        if (text.empty() || text.front() == '-' || text.front() == '+') return false;
        size_t parsed = 0;
        result = std::stoull(text, &parsed, 0);
        return parsed == text.size();
    }
    catch (...)
    {
        return false;
    }
}

const char* OffsetKindName(OffsetKind kind)
{
    switch (kind)
    {
    case OffsetKind::GlobalRva: return "GlobalRva";
    case OffsetKind::StructureField: return "StructureField";
    case OffsetKind::FunctionRva: return "FunctionRva";
    case OffsetKind::ImportRva: return "ImportRva";
    case OffsetKind::ExportRva: return "ExportRva";
    case OffsetKind::PatternMatch: return "PatternMatch";
    default: return "UserDefined";
    }
}

bool ParseOffsetKind(const std::string& value, OffsetKind& kind)
{
    static const std::map<std::string, OffsetKind> values = {
        {"GlobalRva", OffsetKind::GlobalRva}, {"StructureField", OffsetKind::StructureField},
        {"FunctionRva", OffsetKind::FunctionRva}, {"ImportRva", OffsetKind::ImportRva},
        {"ExportRva", OffsetKind::ExportRva}, {"PatternMatch", OffsetKind::PatternMatch},
        {"UserDefined", OffsetKind::UserDefined}
    };
    const auto found = values.find(value);
    if (found == values.end()) return false;
    kind = found->second;
    return true;
}

const char* EvidenceName(EvidenceLevel level)
{
    switch (level)
    {
    case EvidenceLevel::Known: return "Known";
    case EvidenceLevel::Inferred: return "Inferred";
    case EvidenceLevel::Heuristic: return "Heuristic";
    case EvidenceLevel::Partial: return "Partial";
    default: return "Unknown";
    }
}

EvidenceLevel ParseEvidence(const std::string& value)
{
    if (value == "Known") return EvidenceLevel::Known;
    if (value == "Inferred") return EvidenceLevel::Inferred;
    if (value == "Heuristic") return EvidenceLevel::Heuristic;
    if (value == "Partial") return EvidenceLevel::Partial;
    return EvidenceLevel::Unknown;
}

const char* AccessName(DataAccessType access)
{
    switch (access)
    {
    case DataAccessType::Read: return "Read";
    case DataAccessType::Write: return "Write";
    case DataAccessType::ReadWrite: return "ReadWrite";
    default: return "Address";
    }
}

DataAccessType ParseAccess(const std::string& value)
{
    if (value == "Read") return DataAccessType::Read;
    if (value == "Write") return DataAccessType::Write;
    if (value == "ReadWrite") return DataAccessType::ReadWrite;
    return DataAccessType::Address;
}

const char* RelationshipName(SignatureTargetKind kind)
{
    switch (kind)
    {
    case SignatureTargetKind::FunctionRva: return "FunctionRva";
    case SignatureTargetKind::RipRelativeOperand: return "RipRelativeOperand";
    case SignatureTargetKind::FieldDisplacement: return "FieldDisplacement";
    default: return "MatchAddress";
    }
}

SignatureTargetKind ParseRelationship(const std::string& value)
{
    if (value == "FunctionRva") return SignatureTargetKind::FunctionRva;
    if (value == "RipRelativeOperand") return SignatureTargetKind::RipRelativeOperand;
    if (value == "FieldDisplacement") return SignatureTargetKind::FieldDisplacement;
    return SignatureTargetKind::MatchAddress;
}

json SerializeSignature(const SignatureRecord& signature)
{
    json value;
    value["stable_id"] = signature.stableId;
    value["pattern"] = SignatureEngine::FormatPattern(signature.pattern);
    value["relationship"] = {
        {"kind", RelationshipName(signature.relationship.kind)},
        {"instruction_offset", signature.relationship.instructionOffset},
        {"operand_index", signature.relationship.operandIndex},
        {"target_offset", signature.relationship.targetOffset}
    };
    value["target_function"] = Hex(signature.targetFunction);
    value["target_offset"] = Hex(signature.targetOffset);
    value["match_count"] = signature.matchCount;
    value["source_version"] = signature.sourceVersion;
    value["evidence_score"] = signature.evidenceScore;
    return value;
}

} // namespace

bool ComputeModuleIdentity(const std::vector<uint8_t>& bytes, const PEInfo& pe,
                           const std::string& moduleName, ModuleIdentity& identity,
                           std::string& error)
{
    identity = {};
    error.clear();
    if (bytes.empty() || !pe.valid)
    {
        error = "Module identity requires non-empty bytes and valid PE metadata";
        return false;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD hashLength = 0;
    DWORD received = 0;
    std::vector<uint8_t> object;
    std::vector<uint8_t> digest;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status >= 0)
        status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &received, 0);
    if (status >= 0)
        status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &received, 0);
    if (status >= 0)
    {
        object.resize(objectLength);
        digest.resize(hashLength);
        status = BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0);
    }
    size_t offset = 0;
    while (status >= 0 && offset < bytes.size())
    {
        const ULONG chunk = static_cast<ULONG>(std::min<size_t>(bytes.size() - offset,
            (std::numeric_limits<ULONG>::max)()));
        status = BCryptHashData(hash, const_cast<PUCHAR>(bytes.data() + offset), chunk, 0);
        offset += chunk;
    }
    if (status >= 0)
        status = BCryptFinishHash(hash, digest.data(), hashLength, 0);
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0)
    {
        error = "Windows SHA-256 provider failed";
        return false;
    }

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (uint8_t byte : digest)
        hex << std::setw(2) << static_cast<unsigned>(byte);
    identity.name = moduleName;
    identity.sha256 = hex.str();
    identity.peTimestamp = pe.timestamp;
    identity.imageSize = pe.sizeOfImage;
    identity.imageBase = pe.imageBase;
    identity.pdbGuid = pe.pdbGuid;
    identity.pdbAge = pe.pdbAge;
    return true;
}

std::string SerializeOffsetProject(const OffsetProject& project)
{
    json root;
    root["schema_version"] = project.schemaVersion;
    root["module"] = {
        {"name", project.module.name}, {"sha256", project.module.sha256},
        {"pe_timestamp", project.module.peTimestamp}, {"image_size", project.module.imageSize},
        {"image_base", Hex(project.module.imageBase)}, {"file_version", project.module.fileVersion},
        {"pdb_guid", project.module.pdbGuid}, {"pdb_age", project.module.pdbAge}
    };
    root["offsets"] = json::array();
    for (const auto& offset : project.offsets)
    {
        root["offsets"].push_back({
            {"stable_id", offset.stableId}, {"name", offset.name},
            {"kind", OffsetKindName(offset.kind)}, {"address", Hex(offset.address)},
            {"rva", Hex(offset.rva)}, {"field_offset", offset.fieldOffset},
            {"module", offset.module}, {"section", offset.section},
            {"source_function", Hex(offset.sourceFunction)},
            {"source_instruction", Hex(offset.sourceInstruction)},
            {"access", AccessName(offset.accessType)}, {"operand_width", offset.operandWidth},
            {"evidence", EvidenceName(offset.evidence)}, {"evidence_score", offset.evidenceScore},
            {"provenance", offset.provenance}
        });
    }
    root["signatures"] = json::array();
    for (const auto& signature : project.signatures)
        root["signatures"].push_back(SerializeSignature(signature));
    return root.dump(2);
}

bool ParseOffsetProject(const std::string& jsonText, OffsetProject& project, std::string& error)
{
    project = {};
    error.clear();
    try
    {
        const json root = json::parse(jsonText);
        if (!root.is_object() || root.value("schema_version", 0U) != 1 ||
            !root.contains("module") || !root["module"].is_object() ||
            !root.contains("offsets") || !root["offsets"].is_array())
        {
            error = "Unsupported or malformed offset project schema";
            return false;
        }
        if ((root.contains("signatures") && !root["signatures"].is_array()) ||
            root["offsets"].size() > 100000 ||
            (root.contains("signatures") && root["signatures"].size() > 10000))
        {
            error = "Offset project signatures must be an array and remain within import limits";
            return false;
        }
        project.schemaVersion = 1;
        const auto& module = root["module"];
        project.module.name = module.value("name", "");
        project.module.sha256 = module.value("sha256", "");
        project.module.peTimestamp = module.value("pe_timestamp", 0U);
        project.module.imageSize = module.value("image_size", 0U);
        if (!ParseUnsigned(module.value("image_base", json("0x0")), project.module.imageBase))
        {
            error = "Invalid module image_base";
            return false;
        }
        project.module.fileVersion = module.value("file_version", "");
        project.module.pdbGuid = module.value("pdb_guid", "");
        project.module.pdbAge = module.value("pdb_age", 0U);

        for (const auto& value : root["offsets"])
        {
            if (!value.is_object()) throw std::runtime_error("offset entry is not an object");
            OffsetRecord offset;
            offset.stableId = value.value("stable_id", "");
            offset.name = value.value("name", "");
            if (!ParseOffsetKind(value.value("kind", ""), offset.kind) ||
                !ParseUnsigned(value.value("address", json("0x0")), offset.address) ||
                !ParseUnsigned(value.value("rva", json("0x0")), offset.rva))
                throw std::runtime_error("invalid offset kind or address");
            offset.fieldOffset = value.value("field_offset", int64_t{0});
            offset.module = value.value("module", "");
            offset.section = value.value("section", "");
            if (!ParseUnsigned(value.value("source_function", json("0x0")), offset.sourceFunction) ||
                !ParseUnsigned(value.value("source_instruction", json("0x0")), offset.sourceInstruction))
                throw std::runtime_error("invalid source address");
            offset.accessType = ParseAccess(value.value("access", "Address"));
            offset.operandWidth = value.value("operand_width", uint8_t{0});
            offset.evidence = ParseEvidence(value.value("evidence", "Unknown"));
            offset.evidenceScore = value.value("evidence_score", 0U);
            if (value.contains("provenance"))
                offset.provenance = value["provenance"].get<std::vector<std::string>>();
            project.offsets.push_back(std::move(offset));
        }

        if (root.contains("signatures") && root["signatures"].is_array())
        {
            for (const auto& value : root["signatures"])
            {
                SignatureRecord signature;
                signature.stableId = value.value("stable_id", "");
                signature.pattern = PatternScanner::ParsePattern(value.value("pattern", ""));
                if (signature.pattern.empty()) throw std::runtime_error("invalid signature pattern");
                if (value.contains("relationship") && value["relationship"].is_object())
                {
                    const auto& relationship = value["relationship"];
                    signature.relationship.kind = ParseRelationship(relationship.value("kind", "MatchAddress"));
                    signature.relationship.instructionOffset = relationship.value("instruction_offset", 0U);
                    signature.relationship.operandIndex = relationship.value("operand_index", uint8_t{0});
                    signature.relationship.targetOffset = relationship.value("target_offset", int64_t{0});
                }
                if (!ParseUnsigned(value.value("target_function", json("0x0")), signature.targetFunction) ||
                    !ParseUnsigned(value.value("target_offset", json("0x0")), signature.targetOffset))
                    throw std::runtime_error("invalid signature target");
                signature.matchCount = value.value("match_count", size_t{0});
                signature.sourceVersion = value.value("source_version", "");
                signature.evidenceScore = value.value("evidence_score", 0U);
                project.signatures.push_back(std::move(signature));
            }
        }
        return true;
    }
    catch (const std::exception& exception)
    {
        error = std::string("Invalid offset project JSON: ") + exception.what();
        project = {};
        return false;
    }
}

std::string SanitizeCppIdentifier(const std::string& value)
{
    std::string result;
    result.reserve(value.size() + 1);
    for (unsigned char character : value)
        result.push_back(std::isalnum(character) || character == '_' ? static_cast<char>(character) : '_');
    if (result.empty()) result = "offset";
    if (std::isdigit(static_cast<unsigned char>(result.front()))) result.insert(result.begin(), '_');
    return result;
}

std::string ExportOffsetHeader(const OffsetProject& project)
{
    std::ostringstream stream;
    stream << "#pragma once\n\n#include <cstddef>\n#include <cstdint>\n\nnamespace openreverse_offsets {\n";
    std::map<std::string, size_t> duplicates;
    for (const auto& offset : project.offsets)
    {
        std::string identifier = SanitizeCppIdentifier(offset.name);
        const size_t duplicate = duplicates[identifier]++;
        if (duplicate != 0) identifier += "_" + std::to_string(duplicate + 1);
        if (offset.kind == OffsetKind::StructureField)
        {
            const uint64_t magnitude = offset.fieldOffset < 0
                ? static_cast<uint64_t>(-(offset.fieldOffset + 1)) + 1
                : static_cast<uint64_t>(offset.fieldOffset);
            stream << "inline constexpr std::ptrdiff_t " << identifier << " = "
                   << (offset.fieldOffset < 0 ? "-" : "") << Hex(magnitude) << ";\n";
        }
        else
            stream << "inline constexpr std::uintptr_t " << identifier << " = "
                   << Hex(offset.rva) << ";\n";
    }
    stream << "}\n";
    return stream.str();
}

} // namespace openreverse
