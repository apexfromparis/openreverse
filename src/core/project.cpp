#include "project.h"

#include <bcrypt.h>
#include <nlohmann/json.hpp>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace openreverse {

namespace {

using json = nlohmann::json;

constexpr uint64_t kMaximumProjectBytes = 16ULL * 1024ULL * 1024ULL;
constexpr size_t kMaximumAnnotations = 200000;
constexpr size_t kMaximumBookmarks = 100000;
constexpr size_t kMaximumStructures = 20000;
constexpr size_t kMaximumStructureFields = 200000;
constexpr size_t kMaximumMigrations = 100000;
constexpr size_t kMaximumSettings = 256;
constexpr size_t kMaximumPanels = 64;
constexpr size_t kMaximumExtensionStates = 128;
constexpr size_t kMaximumExtensionStateBytes = 256 * 1024;
constexpr size_t kMaximumExtensionStateNodes = 10000;
constexpr size_t kMaximumExtensionStateDepth = 16;
constexpr size_t kMaximumComparisonFunctions = 200000;
constexpr size_t kMaximumComparisonCandidates = 1000000;
constexpr size_t kMaximumComparisonMigrations = 400000;
constexpr size_t kMaximumComparisonEvidence = 4000000;
constexpr size_t kMaximumNameLength = 1024;
constexpr size_t kMaximumCommentLength = 65536;

std::atomic<uint64_t> temporaryCounter{0};

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

std::wstring Widen(const std::string& value)
{
    if (value.empty()) return {};
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (count <= 0) return {};
    std::wstring result(static_cast<size_t>(count), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.c_str(),
        static_cast<int>(value.size()), result.data(), count) != count)
        return {};
    return result;
}

std::string WindowsError(const char* operation, DWORD error)
{
    return std::string(operation) + " failed with Windows error " + std::to_string(error);
}

bool IsSha256(const std::string& value)
{
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return std::isxdigit(character) != 0;
    });
}

bool EqualDigest(const std::string& left, const std::string& right)
{
    if (left.size() != right.size()) return false;
    unsigned char difference = 0;
    for (size_t index = 0; index < left.size(); ++index)
        difference |= static_cast<unsigned char>(
            std::tolower(static_cast<unsigned char>(left[index])) ^
            std::tolower(static_cast<unsigned char>(right[index])));
    return difference == 0;
}

bool IsExtensionId(const std::string& id)
{
    if (id.size() < 3 || id.size() > 128 ||
        !std::isalnum(static_cast<unsigned char>(id.front())))
        return false;
    bool previousDot = false;
    for (unsigned char character : id)
    {
        const bool dot = character == '.';
        if (!(std::islower(character) || std::isdigit(character) || dot || character == '-'))
            return false;
        if (dot && previousDot) return false;
        previousDot = dot;
    }
    return !previousDot && id.find('.') != std::string::npos;
}

bool ValidateExtensionStateNode(const json& value, size_t depth, size_t& nodes)
{
    if (depth > kMaximumExtensionStateDepth || ++nodes > kMaximumExtensionStateNodes)
        return false;
    if (value.is_string()) return value.get_ref<const std::string&>().size() <= kMaximumCommentLength;
    if (value.is_number_float()) return std::isfinite(value.get<double>());
    if (value.is_array())
    {
        if (value.size() > 4096) return false;
        for (const auto& child : value)
            if (!ValidateExtensionStateNode(child, depth + 1, nodes)) return false;
    }
    else if (value.is_object())
    {
        if (value.size() > 4096) return false;
        for (const auto& [key, child] : value.items())
            if (key.size() > kMaximumNameLength ||
                !ValidateExtensionStateNode(child, depth + 1, nodes)) return false;
    }
    return !value.is_binary() && !value.is_discarded();
}

bool ParseExtensionState(const std::string& extensionId, const std::string& text,
                         json& state, std::string& error)
{
    if (!IsExtensionId(extensionId))
    {
        error = "Extension state ID is invalid";
        return false;
    }
    if (text.empty() || text.size() > kMaximumExtensionStateBytes)
    {
        error = "Extension state is empty or exceeds 256 KiB";
        return false;
    }
    try
    {
        state = json::parse(text);
    }
    catch (const std::exception& exception)
    {
        error = std::string("Extension state JSON is invalid: ") + exception.what();
        return false;
    }
    size_t nodes = 0;
    if (!state.is_object() || !ValidateExtensionStateNode(state, 0, nodes))
    {
        error = "Extension state must be a bounded JSON object";
        return false;
    }
    return true;
}

bool FinishSha256(BCRYPT_ALG_HANDLE algorithm, BCRYPT_HASH_HANDLE hash,
                  std::vector<uint8_t>& object, std::string& digest, std::string& error)
{
    DWORD hashLength = 0;
    DWORD received = 0;
    NTSTATUS status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &received, 0);
    std::vector<uint8_t> bytes;
    if (status >= 0)
    {
        bytes.resize(hashLength);
        status = BCryptFinishHash(hash, bytes.data(), hashLength, 0);
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    object.clear();
    if (status < 0)
    {
        error = "Windows SHA-256 provider failed";
        return false;
    }
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (uint8_t byte : bytes)
        stream << std::setw(2) << static_cast<unsigned>(byte);
    digest = stream.str();
    return true;
}

bool StartSha256(BCRYPT_ALG_HANDLE& algorithm, BCRYPT_HASH_HANDLE& hash,
                 std::vector<uint8_t>& object, std::string& error)
{
    DWORD objectLength = 0;
    DWORD received = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status >= 0)
        status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &received, 0);
    if (status >= 0)
    {
        object.resize(objectLength);
        status = BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0);
    }
    if (status >= 0) return true;
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    error = "Windows SHA-256 provider initialization failed";
    return false;
}

bool Sha256Bytes(const std::string& value, std::string& digest, std::string& error)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<uint8_t> object;
    if (!StartSha256(algorithm, hash, object, error)) return false;
    size_t offset = 0;
    NTSTATUS status = 0;
    while (status >= 0 && offset < value.size())
    {
        const ULONG chunk = static_cast<ULONG>(std::min<size_t>(value.size() - offset,
            (std::numeric_limits<ULONG>::max)()));
        status = BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(value.data() + offset)), chunk, 0);
        offset += chunk;
    }
    if (status < 0)
    {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        error = "Windows SHA-256 hashing failed";
        return false;
    }
    return FinishSha256(algorithm, hash, object, digest, error);
}

const char* TargetKindName(ProjectTargetKind kind)
{
    switch (kind)
    {
    case ProjectTargetKind::MappedDump: return "mapped-dump";
    case ProjectTargetKind::RawDump: return "raw-dump";
    case ProjectTargetKind::MinidumpModule: return "minidump-module";
    case ProjectTargetKind::LiveProcess: return "live-process";
    default: return "pe-file";
    }
}

bool ParseTargetKind(const std::string& value, ProjectTargetKind& kind)
{
    if (value == "pe-file") kind = ProjectTargetKind::PEFile;
    else if (value == "mapped-dump") kind = ProjectTargetKind::MappedDump;
    else if (value == "raw-dump") kind = ProjectTargetKind::RawDump;
    else if (value == "minidump-module") kind = ProjectTargetKind::MinidumpModule;
    else if (value == "live-process") kind = ProjectTargetKind::LiveProcess;
    else return false;
    return true;
}

const char* EvidenceName(EvidenceLevel evidence)
{
    switch (evidence)
    {
    case EvidenceLevel::Known: return "known";
    case EvidenceLevel::Inferred: return "inferred";
    case EvidenceLevel::Heuristic: return "heuristic";
    case EvidenceLevel::Partial: return "partial";
    default: return "unknown";
    }
}

EvidenceLevel ParseEvidence(const std::string& value)
{
    if (value == "known") return EvidenceLevel::Known;
    if (value == "inferred") return EvidenceLevel::Inferred;
    if (value == "heuristic") return EvidenceLevel::Heuristic;
    if (value == "partial") return EvidenceLevel::Partial;
    return EvidenceLevel::Unknown;
}

const char* OffsetKindName(OffsetKind kind)
{
    switch (kind)
    {
    case OffsetKind::GlobalRva: return "global-rva";
    case OffsetKind::StructureField: return "structure-field";
    case OffsetKind::FunctionRva: return "function-rva";
    case OffsetKind::ImportRva: return "import-rva";
    case OffsetKind::ExportRva: return "export-rva";
    case OffsetKind::PatternMatch: return "pattern-match";
    default: return "user-defined";
    }
}

bool ParseOffsetKind(const std::string& value, OffsetKind& kind)
{
    if (value == "global-rva") kind = OffsetKind::GlobalRva;
    else if (value == "structure-field") kind = OffsetKind::StructureField;
    else if (value == "function-rva") kind = OffsetKind::FunctionRva;
    else if (value == "import-rva") kind = OffsetKind::ImportRva;
    else if (value == "export-rva") kind = OffsetKind::ExportRva;
    else if (value == "pattern-match") kind = OffsetKind::PatternMatch;
    else if (value == "user-defined") kind = OffsetKind::UserDefined;
    else return false;
    return true;
}

json ModuleJson(const ModuleIdentity& module)
{
    return {
        {"name", module.name}, {"sha256", module.sha256},
        {"pe_timestamp", module.peTimestamp}, {"image_size", module.imageSize},
        {"image_base", Hex(module.imageBase)}, {"file_version", module.fileVersion},
        {"pdb_guid", module.pdbGuid}, {"pdb_age", module.pdbAge}
    };
}

bool ReadBoundedString(const json& object, const char* key, std::string& output,
                       size_t maximum, bool required = false)
{
    if (!object.contains(key))
    {
        output.clear();
        return !required;
    }
    if (!object[key].is_string()) return false;
    output = object[key].get<std::string>();
    return output.size() <= maximum && (!required || !output.empty());
}

bool ParseModule(const json& value, ModuleIdentity& module)
{
    if (!value.is_object() ||
        !ReadBoundedString(value, "name", module.name, kMaximumNameLength) ||
        !ReadBoundedString(value, "sha256", module.sha256, 64) ||
        !ReadBoundedString(value, "file_version", module.fileVersion, kMaximumNameLength) ||
        !ReadBoundedString(value, "pdb_guid", module.pdbGuid, kMaximumNameLength) ||
        !ParseUnsigned(value.value("image_base", json("0x0")), module.imageBase))
        return false;
    module.peTimestamp = value.value("pe_timestamp", 0U);
    module.imageSize = value.value("image_size", 0U);
    module.pdbAge = value.value("pdb_age", 0U);
    return module.sha256.empty() || IsSha256(module.sha256);
}

json StructureJson(const ProjectStructure& structure)
{
    json fields = json::array();
    for (const auto& field : structure.fields)
    {
        fields.push_back({
            {"offset", field.offset}, {"size", field.size},
            {"reads", field.readCount}, {"writes", field.writeCount},
            {"addresses", field.addressCount}, {"name", field.name},
            {"type", field.type}, {"comment", field.comment}
        });
    }
    return {
        {"stable_id", structure.stableId}, {"name", structure.name},
        {"source_function_rva", Hex(structure.sourceFunctionRva)},
        {"base_register", structure.baseRegister},
        {"argument_index", structure.argumentIndex},
        {"estimated_size", Hex(structure.estimatedSize)},
        {"evidence", EvidenceName(structure.evidence)},
        {"evidence_score", structure.evidenceScore},
        {"accepted", structure.accepted}, {"fields", std::move(fields)}
    };
}

bool ParseStructure(const json& value, ProjectStructure& structure, size_t& totalFields)
{
    if (!value.is_object() || !value.contains("fields") || !value["fields"].is_array() ||
        !ReadBoundedString(value, "stable_id", structure.stableId, kMaximumNameLength) ||
        !ReadBoundedString(value, "name", structure.name, kMaximumNameLength) ||
        !ReadBoundedString(value, "base_register", structure.baseRegister, 64) ||
        !ParseUnsigned(value.value("source_function_rva", json("0x0")), structure.sourceFunctionRva) ||
        !ParseUnsigned(value.value("estimated_size", json("0x0")), structure.estimatedSize))
        return false;
    if (totalFields + value["fields"].size() > kMaximumStructureFields) return false;
    structure.argumentIndex = value.value("argument_index", uint8_t{0});
    structure.evidence = ParseEvidence(value.value("evidence", "unknown"));
    structure.evidenceScore = value.value("evidence_score", 0U);
    structure.accepted = value.value("accepted", false);
    for (const auto& fieldValue : value["fields"])
    {
        if (!fieldValue.is_object()) return false;
        ProjectStructureField field;
        field.offset = fieldValue.value("offset", int64_t{0});
        field.size = fieldValue.value("size", uint8_t{0});
        field.readCount = fieldValue.value("reads", size_t{0});
        field.writeCount = fieldValue.value("writes", size_t{0});
        field.addressCount = fieldValue.value("addresses", size_t{0});
        if (!ReadBoundedString(fieldValue, "name", field.name, kMaximumNameLength) ||
            !ReadBoundedString(fieldValue, "type", field.type, kMaximumNameLength) ||
            !ReadBoundedString(fieldValue, "comment", field.comment, kMaximumCommentLength))
            return false;
        structure.fields.push_back(std::move(field));
        ++totalFields;
    }
    return true;
}

json VersionTargetJson(const VersionTargetIdentity& target)
{
    return {{"name", target.name}, {"path", target.path}, {"sha256", target.sha256},
        {"architecture", target.architecture}, {"pe_timestamp", target.peTimestamp},
        {"size_of_image", target.sizeOfImage}, {"image_base", Hex(target.imageBase)}};
}

json VersionEvidenceJson(const VersionEvidence& evidence)
{
    return {{"kind", VersionEvidenceKindName(evidence.kind)}, {"score", evidence.score},
        {"old_count", evidence.oldCount}, {"new_count", evidence.newCount},
        {"detail", evidence.detail}};
}

json VersionChangesJson(const FunctionChangeSummary& changes)
{
    return {{"instruction_delta", changes.instructionDelta},
        {"basic_block_delta", changes.basicBlockDelta}, {"edge_delta", changes.edgeDelta},
        {"call_delta", changes.callDelta}, {"added_strings", changes.addedStrings},
        {"removed_strings", changes.removedStrings}, {"added_imports", changes.addedImports},
        {"removed_imports", changes.removedImports}, {"added_globals", changes.addedGlobals},
        {"removed_globals", changes.removedGlobals}, {"added_fields", changes.addedFields},
        {"removed_fields", changes.removedFields}};
}

json VersionComparisonJson(const VersionComparison& comparison)
{
    json functions = json::array();
    for (const auto& function : comparison.functions)
    {
        json candidates = json::array();
        for (const auto& candidate : function.candidates)
        {
            json evidence = json::array();
            for (const auto& item : candidate.evidence) evidence.push_back(VersionEvidenceJson(item));
            candidates.push_back({{"new_rva", Hex(candidate.newRva)}, {"new_name", candidate.newName},
                {"similarity_score", candidate.similarityScore},
                {"suggested_state", VersionMatchStateName(candidate.suggestedState)},
                {"evidence", std::move(evidence)}, {"changes", VersionChangesJson(candidate.changes)}});
        }
        functions.push_back({{"stable_id", function.stableId}, {"old_rva", Hex(function.oldRva)},
            {"old_name", function.oldName},
            {"suggested_state", VersionMatchStateName(function.suggestedState)},
            {"decision", VersionDecisionName(function.decision)},
            {"decision_new_rva", Hex(function.decisionNewRva)}, {"candidates", std::move(candidates)}});
    }
    json migrations = json::array();
    for (const auto& migration : comparison.migrations)
    {
        json evidence = json::array();
        for (const auto& item : migration.evidence) evidence.push_back(VersionEvidenceJson(item));
        migrations.push_back({{"stable_id", migration.stableId},
            {"kind", VersionMigrationKindName(migration.kind)},
            {"offset_kind", OffsetKindName(migration.offsetKind)},
            {"old_rva", Hex(migration.oldRva)}, {"new_rva", Hex(migration.newRva)},
            {"old_value", migration.oldValue}, {"new_value", migration.newValue},
            {"old_support_rva", Hex(migration.oldSupportRva)},
            {"new_support_rva", Hex(migration.newSupportRva)},
            {"suggested_state", VersionMatchStateName(migration.suggestedState)},
            {"decision", VersionDecisionName(migration.decision)}, {"evidence", std::move(evidence)}});
    }
    json newFunctions = json::array();
    for (uint64_t rva : comparison.newFunctionRvas) newFunctions.push_back(Hex(rva));
    return {{"algorithm_version", comparison.algorithmVersion},
        {"old_target", VersionTargetJson(comparison.oldTarget)},
        {"new_target", VersionTargetJson(comparison.newTarget)},
        {"functions", std::move(functions)}, {"new_functions", std::move(newFunctions)},
        {"migrations", std::move(migrations)},
        {"indexed_candidate_pairs", comparison.indexedCandidatePairs},
        {"scored_candidate_pairs", comparison.scoredCandidatePairs},
        {"signature_scans_performed", comparison.signatureScansPerformed},
        {"candidate_budget_reached", comparison.candidateBudgetReached}};
}

json BuildProjectRoot(const OpenReverseProject& project)
{
    OffsetProject offsetProject;
    offsetProject.module = project.target.module;
    offsetProject.offsets = project.analysis.offsets;
    offsetProject.signatures = project.analysis.signatures;
    const json offsetDocument = json::parse(SerializeOffsetProject(offsetProject));

    json structures = json::array();
    for (const auto& structure : project.analysis.structures)
        structures.push_back(StructureJson(structure));

    json functions = json::array();
    for (const auto& function : project.user.functions)
        functions.push_back({{"rva", Hex(function.rva)}, {"name", function.name},
                             {"comment", function.comment}});

    json bookmarks = json::array();
    for (const auto& bookmark : project.user.bookmarks)
        bookmarks.push_back({{"rva", Hex(bookmark.rva)}, {"label", bookmark.label},
                             {"comment", bookmark.comment}, {"color", bookmark.color}});

    json userStructures = json::array();
    for (const auto& structure : project.user.structures)
        userStructures.push_back(StructureJson(structure));

    json migrations = json::array();
    for (const auto& migration : project.user.migrations)
    {
        migrations.push_back({
            {"stable_id", migration.stableId}, {"kind", OffsetKindName(migration.kind)},
            {"old_rva", Hex(migration.oldRva)}, {"new_rva", Hex(migration.newRva)},
            {"old_value", migration.oldValue}, {"new_value", migration.newValue},
            {"decision", migration.decision == ProjectMigrationDecisionKind::Accepted
                ? "accepted" : "rejected"},
            {"evidence", migration.evidence}
        });
    }

    json extensionState = json::object();
    for (const auto& [extensionId, stateText] : project.extensionState)
    {
        json state;
        std::string error;
        if (!ParseExtensionState(extensionId, stateText, state, error))
            throw std::runtime_error(error);
        extensionState[extensionId] = std::move(state);
    }

    json root = {
        {"format", "openreverse-project"},
        {"version", project.version},
        {"target", {
            {"kind", TargetKindName(project.target.kind)},
            {"path", project.target.path},
            {"sha256", project.target.sha256},
            {"architecture", project.target.architecture},
            {"image_base", Hex(project.target.imageBase)},
            {"module_size", Hex(project.target.moduleSize)},
            {"selected_module_base", Hex(project.target.selectedModuleBase)},
            {"module", ModuleJson(project.target.module)}
        }},
        {"analysis", {
            {"offsets", offsetDocument.at("offsets")},
            {"signatures", offsetDocument.at("signatures")},
            {"structures", std::move(structures)}
        }},
        {"user", {
            {"functions", std::move(functions)},
            {"bookmarks", std::move(bookmarks)},
            {"structures", std::move(userStructures)},
            {"migrations", std::move(migrations)},
            {"settings", project.user.settings}
        }},
        {"ui", {
            {"current_rva", Hex(project.ui.currentRva)},
            {"workspace", project.ui.workspace},
            {"open_panels", project.ui.openPanels}
        }},
        {"extensions", std::move(extensionState)}
    };
    if (project.hasVersionComparison)
        root["version_intelligence"] = VersionComparisonJson(project.versionComparison);
    return root;
}

bool ParseStringVector(const json& value, std::vector<std::string>& output,
                       size_t maximumCount, size_t maximumLength)
{
    if (!value.is_array() || value.size() > maximumCount) return false;
    for (const auto& item : value)
    {
        if (!item.is_string()) return false;
        std::string text = item.get<std::string>();
        if (text.size() > maximumLength) return false;
        output.push_back(std::move(text));
    }
    return true;
}

bool ParseVersionTarget(const json& value, VersionTargetIdentity& target)
{
    uint64_t peTimestamp = 0;
    uint64_t sizeOfImage = 0;
    if (!value.is_object() ||
        !ReadBoundedString(value, "name", target.name, kMaximumNameLength) ||
        !ReadBoundedString(value, "path", target.path, 32768) ||
        !ReadBoundedString(value, "sha256", target.sha256, 64, true) ||
        !IsSha256(target.sha256) ||
        !ReadBoundedString(value, "architecture", target.architecture, 16, true) ||
        !ParseUnsigned(value.value("image_base", json("0x0")), target.imageBase) ||
        !ParseUnsigned(value.value("pe_timestamp", json(0)), peTimestamp) ||
        !ParseUnsigned(value.value("size_of_image", json(0)), sizeOfImage) ||
        peTimestamp > (std::numeric_limits<uint32_t>::max)() ||
        sizeOfImage > (std::numeric_limits<uint32_t>::max)())
        return false;
    target.peTimestamp = static_cast<uint32_t>(peTimestamp);
    target.sizeOfImage = static_cast<uint32_t>(sizeOfImage);
    return true;
}

bool ParseVersionEvidence(const json& value, VersionEvidence& evidence)
{
    std::string kind;
    if (!value.is_object() || !ReadBoundedString(value, "kind", kind, 64, true) ||
        !ParseVersionEvidenceKind(kind, evidence.kind) ||
        !ReadBoundedString(value, "detail", evidence.detail, kMaximumCommentLength))
        return false;
    evidence.score = value.value("score", 0.0);
    evidence.oldCount = value.value("old_count", 0U);
    evidence.newCount = value.value("new_count", 0U);
    return std::isfinite(evidence.score) && evidence.score >= 0.0 && evidence.score <= 1.0;
}

bool ParseVersionChanges(const json& value, FunctionChangeSummary& changes)
{
    if (!value.is_object()) return false;
    changes.instructionDelta = value.value("instruction_delta", int64_t{0});
    changes.basicBlockDelta = value.value("basic_block_delta", int64_t{0});
    changes.edgeDelta = value.value("edge_delta", int64_t{0});
    changes.callDelta = value.value("call_delta", int64_t{0});
    for (const char* key : {"added_strings", "removed_strings", "added_imports", "removed_imports",
                            "added_globals", "removed_globals", "added_fields", "removed_fields"})
        if (!value.contains(key)) return false;
    return ParseStringVector(value["added_strings"], changes.addedStrings, 100000, kMaximumCommentLength) &&
        ParseStringVector(value["removed_strings"], changes.removedStrings, 100000, kMaximumCommentLength) &&
        ParseStringVector(value["added_imports"], changes.addedImports, 100000, kMaximumCommentLength) &&
        ParseStringVector(value["removed_imports"], changes.removedImports, 100000, kMaximumCommentLength) &&
        ParseStringVector(value["added_globals"], changes.addedGlobals, 100000, kMaximumCommentLength) &&
        ParseStringVector(value["removed_globals"], changes.removedGlobals, 100000, kMaximumCommentLength) &&
        ParseStringVector(value["added_fields"], changes.addedFields, 100000, kMaximumCommentLength) &&
        ParseStringVector(value["removed_fields"], changes.removedFields, 100000, kMaximumCommentLength);
}

bool ParseVersionComparison(const json& value, VersionComparison& comparison)
{
    if (!value.is_object() || !value.contains("old_target") || !value.contains("new_target") ||
        !value.contains("functions") || !value["functions"].is_array() ||
        value["functions"].size() > kMaximumComparisonFunctions ||
        !value.contains("new_functions") || !value["new_functions"].is_array() ||
        value["new_functions"].size() > kMaximumComparisonFunctions ||
        !value.contains("migrations") || !value["migrations"].is_array() ||
        value["migrations"].size() > kMaximumComparisonMigrations)
        return false;
    comparison.algorithmVersion = value.value("algorithm_version", 0U);
    if ((comparison.algorithmVersion == 0 ||
         comparison.algorithmVersion > kVersionIntelligenceAlgorithmVersion) ||
        !ParseVersionTarget(value["old_target"], comparison.oldTarget) ||
        !ParseVersionTarget(value["new_target"], comparison.newTarget))
        return false;

    size_t totalCandidates = 0;
    size_t totalEvidence = 0;
    for (const auto& functionValue : value["functions"])
    {
        VersionFunctionMatch function;
        std::string state;
        std::string decision;
        if (!functionValue.is_object() ||
            !ReadBoundedString(functionValue, "stable_id", function.stableId, kMaximumNameLength, true) ||
            !ReadBoundedString(functionValue, "old_name", function.oldName, kMaximumNameLength) ||
            !ReadBoundedString(functionValue, "suggested_state", state, 64, true) ||
            !ReadBoundedString(functionValue, "decision", decision, 32, true) ||
            !ParseVersionMatchState(state, function.suggestedState) ||
            !ParseVersionDecision(decision, function.decision) ||
            !ParseUnsigned(functionValue.value("old_rva", json("0x0")), function.oldRva) ||
            !ParseUnsigned(functionValue.value("decision_new_rva", json("0x0")), function.decisionNewRva) ||
            !functionValue.contains("candidates") || !functionValue["candidates"].is_array())
            return false;
        totalCandidates += functionValue["candidates"].size();
        if (totalCandidates > kMaximumComparisonCandidates) return false;
        for (const auto& candidateValue : functionValue["candidates"])
        {
            VersionFunctionCandidate candidate;
            std::string candidateState;
            if (!candidateValue.is_object() ||
                !ReadBoundedString(candidateValue, "new_name", candidate.newName, kMaximumNameLength) ||
                !ReadBoundedString(candidateValue, "suggested_state", candidateState, 64, true) ||
                !ParseVersionMatchState(candidateState, candidate.suggestedState) ||
                !ParseUnsigned(candidateValue.value("new_rva", json("0x0")), candidate.newRva) ||
                !candidateValue.contains("evidence") || !candidateValue["evidence"].is_array() ||
                !candidateValue.contains("changes") ||
                !ParseVersionChanges(candidateValue["changes"], candidate.changes))
                return false;
            candidate.similarityScore = candidateValue.value("similarity_score", 0.0);
            if (!std::isfinite(candidate.similarityScore) || candidate.similarityScore < 0.0 ||
                candidate.similarityScore > 1.0)
                return false;
            totalEvidence += candidateValue["evidence"].size();
            if (totalEvidence > kMaximumComparisonEvidence) return false;
            for (const auto& evidenceValue : candidateValue["evidence"])
            {
                VersionEvidence evidence;
                if (!ParseVersionEvidence(evidenceValue, evidence)) return false;
                candidate.evidence.push_back(std::move(evidence));
            }
            function.candidates.push_back(std::move(candidate));
        }
        const bool acceptedCandidateExists = function.decision != VersionDecision::Accepted ||
            std::any_of(function.candidates.begin(), function.candidates.end(),
                [&](const VersionFunctionCandidate& candidate) {
                    return candidate.newRva == function.decisionNewRva;
                });
        if (!acceptedCandidateExists ||
            (function.decision != VersionDecision::Accepted && function.decisionNewRva != 0))
            return false;
        comparison.functions.push_back(std::move(function));
    }

    for (const auto& rvaValue : value["new_functions"])
    {
        uint64_t rva = 0;
        if (!ParseUnsigned(rvaValue, rva)) return false;
        comparison.newFunctionRvas.push_back(rva);
    }
    for (const auto& migrationValue : value["migrations"])
    {
        VersionMigrationCandidate migration;
        std::string kind;
        std::string offsetKind;
        std::string state;
        std::string decision;
        if (!migrationValue.is_object() ||
            !ReadBoundedString(migrationValue, "stable_id", migration.stableId, kMaximumNameLength, true) ||
            !ReadBoundedString(migrationValue, "kind", kind, 64, true) ||
            !ReadBoundedString(migrationValue, "offset_kind", offsetKind, 64, true) ||
            !ReadBoundedString(migrationValue, "suggested_state", state, 64, true) ||
            !ReadBoundedString(migrationValue, "decision", decision, 32, true) ||
            !ParseVersionMigrationKind(kind, migration.kind) ||
            !ParseOffsetKind(offsetKind, migration.offsetKind) ||
            !ParseVersionMatchState(state, migration.suggestedState) ||
            !ParseVersionDecision(decision, migration.decision) ||
            !ParseUnsigned(migrationValue.value("old_rva", json("0x0")), migration.oldRva) ||
            !ParseUnsigned(migrationValue.value("new_rva", json("0x0")), migration.newRva) ||
            !ParseUnsigned(migrationValue.value("old_support_rva", json("0x0")), migration.oldSupportRva) ||
            !ParseUnsigned(migrationValue.value("new_support_rva", json("0x0")), migration.newSupportRva) ||
            !migrationValue.contains("evidence") || !migrationValue["evidence"].is_array())
            return false;
        migration.oldValue = migrationValue.value("old_value", int64_t{0});
        migration.newValue = migrationValue.value("new_value", int64_t{0});
        totalEvidence += migrationValue["evidence"].size();
        if (totalEvidence > kMaximumComparisonEvidence) return false;
        for (const auto& evidenceValue : migrationValue["evidence"])
        {
            VersionEvidence evidence;
            if (!ParseVersionEvidence(evidenceValue, evidence)) return false;
            migration.evidence.push_back(std::move(evidence));
        }
        comparison.migrations.push_back(std::move(migration));
    }
    comparison.indexedCandidatePairs = value.value("indexed_candidate_pairs", size_t{0});
    comparison.scoredCandidatePairs = value.value("scored_candidate_pairs", size_t{0});
    comparison.signatureScansPerformed = value.value("signature_scans_performed", size_t{0});
    comparison.candidateBudgetReached = value.value("candidate_budget_reached", false);
    return true;
}

bool MigrateProjectDocument(json& root, uint32_t& version, std::string& error)
{
    while (version < kOpenReverseProjectVersion)
    {
        switch (version)
        {
        default:
            error = "No safe OpenReverse project migration is registered from version " +
                std::to_string(version);
            return false;
        }
    }
    root["version"] = version;
    return true;
}

bool ParseProjectRoot(const json& root, OpenReverseProject& project, std::string& error)
{
    const auto& target = root.at("target");
    const auto& analysis = root.at("analysis");
    const auto& user = root.at("user");
    const auto& ui = root.at("ui");
    if (!target.is_object() || !analysis.is_object() || !user.is_object() || !ui.is_object())
        throw std::runtime_error("project sections must be objects");

    if (!ParseTargetKind(target.value("kind", ""), project.target.kind) ||
        !ReadBoundedString(target, "path", project.target.path, 32768) ||
        !ReadBoundedString(target, "sha256", project.target.sha256, 64, true) ||
        !ReadBoundedString(target, "architecture", project.target.architecture, 16, true) ||
        !ParseUnsigned(target.value("image_base", json("0x0")), project.target.imageBase) ||
        !ParseUnsigned(target.value("module_size", json("0x0")), project.target.moduleSize) ||
        !ParseUnsigned(target.value("selected_module_base", json("0x0")),
                       project.target.selectedModuleBase) ||
        !target.contains("module") || !ParseModule(target["module"], project.target.module) ||
        !IsSha256(project.target.sha256))
        throw std::runtime_error("target metadata is invalid");

    if (!analysis.contains("offsets") || !analysis["offsets"].is_array() ||
        !analysis.contains("signatures") || !analysis["signatures"].is_array() ||
        !analysis.contains("structures") || !analysis["structures"].is_array() ||
        analysis["structures"].size() > kMaximumStructures)
        throw std::runtime_error("analysis collections are invalid or exceed limits");

    json offsetDocument = {
        {"schema_version", 1}, {"module", ModuleJson(project.target.module)},
        {"offsets", analysis["offsets"]}, {"signatures", analysis["signatures"]}
    };
    OffsetProject offsetProject;
    if (!ParseOffsetProject(offsetDocument.dump(), offsetProject, error))
        throw std::runtime_error(error);
    project.analysis.offsets = std::move(offsetProject.offsets);
    project.analysis.signatures = std::move(offsetProject.signatures);

    size_t totalFields = 0;
    for (const auto& value : analysis["structures"])
    {
        ProjectStructure structure;
        if (!ParseStructure(value, structure, totalFields))
            throw std::runtime_error("analysis structure is invalid or exceeds limits");
        project.analysis.structures.push_back(std::move(structure));
    }

    if (!user.contains("functions") || !user["functions"].is_array() ||
        user["functions"].size() > kMaximumAnnotations ||
        !user.contains("bookmarks") || !user["bookmarks"].is_array() ||
        user["bookmarks"].size() > kMaximumBookmarks ||
        !user.contains("structures") || !user["structures"].is_array() ||
        user["structures"].size() > kMaximumStructures ||
        !user.contains("migrations") || !user["migrations"].is_array() ||
        user["migrations"].size() > kMaximumMigrations ||
        !user.contains("settings") || !user["settings"].is_object() ||
        user["settings"].size() > kMaximumSettings)
        throw std::runtime_error("user collections are invalid or exceed limits");

    for (const auto& value : user["functions"])
    {
        ProjectFunctionAnnotation annotation;
        if (!value.is_object() ||
            !ParseUnsigned(value.value("rva", json("0x0")), annotation.rva) ||
            !ReadBoundedString(value, "name", annotation.name, kMaximumNameLength) ||
            !ReadBoundedString(value, "comment", annotation.comment, kMaximumCommentLength))
            throw std::runtime_error("function annotation is invalid");
        project.user.functions.push_back(std::move(annotation));
    }

    for (const auto& value : user["bookmarks"])
    {
        ProjectBookmark bookmark;
        if (!value.is_object() ||
            !ParseUnsigned(value.value("rva", json("0x0")), bookmark.rva) ||
            !ReadBoundedString(value, "label", bookmark.label, kMaximumNameLength) ||
            !ReadBoundedString(value, "comment", bookmark.comment, kMaximumCommentLength))
            throw std::runtime_error("bookmark is invalid");
        bookmark.color = value.value("color", 0U);
        project.user.bookmarks.push_back(std::move(bookmark));
    }

    for (const auto& value : user["structures"])
    {
        ProjectStructure structure;
        if (!ParseStructure(value, structure, totalFields))
            throw std::runtime_error("user structure is invalid or exceeds limits");
        project.user.structures.push_back(std::move(structure));
    }

    for (const auto& value : user["migrations"])
    {
        ProjectMigrationDecision migration;
        std::string decision;
        std::string kind;
        if (!value.is_object() ||
            !ReadBoundedString(value, "stable_id", migration.stableId, kMaximumNameLength, true) ||
            !ReadBoundedString(value, "kind", kind, 64, true) ||
            !ReadBoundedString(value, "decision", decision, 16, true) ||
            !ParseOffsetKind(kind, migration.kind) ||
            !ParseUnsigned(value.value("old_rva", json("0x0")), migration.oldRva) ||
            !ParseUnsigned(value.value("new_rva", json("0x0")), migration.newRva) ||
            !value.contains("evidence") ||
            !ParseStringVector(value["evidence"], migration.evidence, 256, kMaximumCommentLength))
            throw std::runtime_error("migration decision is invalid");
        if (decision == "accepted") migration.decision = ProjectMigrationDecisionKind::Accepted;
        else if (decision == "rejected") migration.decision = ProjectMigrationDecisionKind::Rejected;
        else throw std::runtime_error("migration decision value is invalid");
        migration.oldValue = value.value("old_value", int64_t{0});
        migration.newValue = value.value("new_value", int64_t{0});
        project.user.migrations.push_back(std::move(migration));
    }

    for (const auto& [key, value] : user["settings"].items())
    {
        if (key.size() > kMaximumNameLength || !value.is_string())
            throw std::runtime_error("project setting is invalid");
        std::string setting = value.get<std::string>();
        if (setting.size() > kMaximumCommentLength)
            throw std::runtime_error("project setting exceeds its size limit");
        project.user.settings.emplace(key, std::move(setting));
    }

    if (!ParseUnsigned(ui.value("current_rva", json("0x0")), project.ui.currentRva) ||
        !ReadBoundedString(ui, "workspace", project.ui.workspace, 64, true) ||
        !ui.contains("open_panels") ||
        !ParseStringVector(ui["open_panels"], project.ui.openPanels,
                           kMaximumPanels, kMaximumNameLength))
        throw std::runtime_error("UI state is invalid");
    if (root.contains("version_intelligence"))
    {
        if (!ParseVersionComparison(root["version_intelligence"], project.versionComparison))
            throw std::runtime_error("Version Intelligence state is invalid, unsupported, or exceeds limits");
        project.hasVersionComparison = true;
    }
    if (root.contains("extensions"))
    {
        const auto& extensions = root["extensions"];
        if (!extensions.is_object() || extensions.size() > kMaximumExtensionStates)
            throw std::runtime_error("Extension state collection is invalid or exceeds limits");
        for (const auto& [extensionId, stateValue] : extensions.items())
        {
            const std::string stateText = stateValue.dump();
            json validated;
            std::string stateError;
            if (!ParseExtensionState(extensionId, stateText, validated, stateError))
                throw std::runtime_error(stateError);
            project.extensionState.emplace(extensionId, validated.dump());
        }
    }
    return true;
}

} // namespace

bool ProjectStore::Serialize(const OpenReverseProject& project, std::string& jsonText,
                             std::string& error)
{
    jsonText.clear();
    error.clear();
    try
    {
        if (project.version != kOpenReverseProjectVersion)
        {
            error = "Unsupported OpenReverse project version: " + std::to_string(project.version);
            return false;
        }
        if (!IsSha256(project.target.sha256) || project.target.architecture.empty())
        {
            error = "Project target identity is incomplete";
            return false;
        }
        json root = BuildProjectRoot(project);
        std::string digest;
        if (!Sha256Bytes(root.dump(), digest, error)) return false;
        root["integrity"] = {{"algorithm", "sha256"}, {"digest", digest}};
        jsonText = root.dump(2);
        if (jsonText.size() > kMaximumProjectBytes)
        {
            jsonText.clear();
            error = "OpenReverse project exceeds the 16 MB size limit";
            return false;
        }
        return true;
    }
    catch (const std::exception& exception)
    {
        error = std::string("Could not serialize OpenReverse project: ") + exception.what();
        return false;
    }
}

bool ProjectStore::ValidateExtensionState(const std::string& extensionId,
                                          const std::string& jsonObject,
                                          std::string& canonicalJson,
                                          std::string& error)
{
    canonicalJson.clear();
    error.clear();
    json state;
    if (!ParseExtensionState(extensionId, jsonObject, state, error)) return false;
    canonicalJson = state.dump();
    return canonicalJson.size() <= kMaximumExtensionStateBytes;
}

bool ProjectStore::Parse(const std::string& jsonText, OpenReverseProject& project,
                         std::string& error)
{
    project = {};
    error.clear();
    if (jsonText.empty() || jsonText.size() > kMaximumProjectBytes)
    {
        error = "OpenReverse project is empty or exceeds the 16 MB size limit";
        return false;
    }
    try
    {
        json root = json::parse(jsonText);
        if (!root.is_object() || root.value("format", "") != "openreverse-project")
        {
            error = "File is not an OpenReverse project";
            return false;
        }
        if (!root.contains("version") || !root["version"].is_number_unsigned())
        {
            error = "OpenReverse project version is missing or malformed";
            return false;
        }
        const uint32_t version = root["version"].get<uint32_t>();
        if (version > kOpenReverseProjectVersion)
        {
            error = "Unsupported OpenReverse project version: " + std::to_string(version);
            return false;
        }
        if (!root.contains("target") || !root.contains("analysis") ||
            !root.contains("user") || !root.contains("ui") ||
            !root.contains("integrity") || !root["integrity"].is_object())
        {
            error = "OpenReverse project is missing a required section";
            return false;
        }
        const json integrity = root["integrity"];
        const std::string algorithm = integrity.value("algorithm", "");
        const std::string expectedDigest = integrity.value("digest", "");
        if (algorithm != "sha256" || !IsSha256(expectedDigest))
        {
            error = "OpenReverse project integrity metadata is invalid";
            return false;
        }
        root.erase("integrity");
        std::string actualDigest;
        if (!Sha256Bytes(root.dump(), actualDigest, error)) return false;
        if (!EqualDigest(expectedDigest, actualDigest))
        {
            error = "OpenReverse project integrity check failed";
            return false;
        }
        uint32_t decodedVersion = version;
        if (!MigrateProjectDocument(root, decodedVersion, error)) return false;
        project.version = decodedVersion;
        return ParseProjectRoot(root, project, error);
    }
    catch (const std::exception& exception)
    {
        project = {};
        error = std::string("Invalid OpenReverse project: ") + exception.what();
        return false;
    }
}

bool ProjectStore::SaveAtomic(const std::string& path, const OpenReverseProject& project,
                              std::string& error)
{
    error.clear();
    std::string jsonText;
    if (!Serialize(project, jsonText, error)) return false;
    const std::wstring destination = Widen(path);
    if (destination.empty())
    {
        error = "Project path is empty or is not valid UTF-8";
        return false;
    }
    const std::wstring temporary = destination + L".tmp." + std::to_wstring(GetCurrentProcessId()) +
        L"." + std::to_wstring(++temporaryCounter);
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        error = WindowsError("Creating project staging file", GetLastError());
        return false;
    }
    bool success = true;
    size_t offset = 0;
    while (offset < jsonText.size())
    {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(jsonText.size() - offset,
            (std::numeric_limits<DWORD>::max)()));
        DWORD written = 0;
        if (!WriteFile(file, jsonText.data() + offset, chunk, &written, nullptr) || written != chunk)
        {
            error = WindowsError("Writing project staging file", GetLastError());
            success = false;
            break;
        }
        offset += written;
    }
    if (success && !FlushFileBuffers(file))
    {
        error = WindowsError("Flushing project staging file", GetLastError());
        success = false;
    }
    CloseHandle(file);
    if (!success)
    {
        DeleteFileW(temporary.c_str());
        return false;
    }

    const DWORD attributes = GetFileAttributesW(destination.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES)
    {
        if (!ReplaceFileW(destination.c_str(), temporary.c_str(), nullptr,
                          REPLACEFILE_WRITE_THROUGH, nullptr, nullptr))
        {
            error = WindowsError("Replacing OpenReverse project", GetLastError());
            DeleteFileW(temporary.c_str());
            return false;
        }
    }
    else if (!MoveFileExW(temporary.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH))
    {
        error = WindowsError("Publishing OpenReverse project", GetLastError());
        DeleteFileW(temporary.c_str());
        return false;
    }
    return true;
}

bool ProjectStore::Load(const std::string& path, OpenReverseProject& project,
                        std::string& error)
{
    project = {};
    error.clear();
    const std::wstring widePath = Widen(path);
    if (widePath.empty())
    {
        error = "Project path is empty or is not valid UTF-8";
        return false;
    }
    HANDLE file = CreateFileW(widePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        error = WindowsError("Opening OpenReverse project", GetLastError());
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        static_cast<uint64_t>(size.QuadPart) > kMaximumProjectBytes)
    {
        CloseHandle(file);
        error = "OpenReverse project is empty or exceeds the 16 MB size limit";
        return false;
    }
    std::string jsonText(static_cast<size_t>(size.QuadPart), '\0');
    size_t offset = 0;
    while (offset < jsonText.size())
    {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(jsonText.size() - offset,
            (std::numeric_limits<DWORD>::max)()));
        DWORD received = 0;
        if (!ReadFile(file, jsonText.data() + offset, chunk, &received, nullptr) || received == 0)
        {
            CloseHandle(file);
            error = WindowsError("Reading OpenReverse project", GetLastError());
            return false;
        }
        offset += received;
    }
    CloseHandle(file);
    return Parse(jsonText, project, error);
}

bool ProjectStore::ComputeFileSha256(const std::string& path, std::string& sha256,
                                     std::string& error)
{
    sha256.clear();
    error.clear();
    const std::wstring widePath = Widen(path);
    if (widePath.empty())
    {
        error = "Target path is empty or is not valid UTF-8";
        return false;
    }
    HANDLE file = CreateFileW(widePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE |
                              FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        error = WindowsError("Opening project target", GetLastError());
        return false;
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<uint8_t> object;
    if (!StartSha256(algorithm, hash, object, error))
    {
        CloseHandle(file);
        return false;
    }
    std::vector<uint8_t> buffer(1024 * 1024);
    NTSTATUS status = 0;
    for (;;)
    {
        DWORD received = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &received, nullptr))
        {
            error = WindowsError("Reading project target", GetLastError());
            status = -1;
            break;
        }
        if (received == 0) break;
        status = BCryptHashData(hash, buffer.data(), received, 0);
        if (status < 0)
        {
            error = "Windows SHA-256 hashing failed";
            break;
        }
    }
    CloseHandle(file);
    if (status < 0)
    {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }
    return FinishSha256(algorithm, hash, object, sha256, error);
}

ProjectTargetVerification ProjectStore::VerifyTarget(const OpenReverseProject& project,
                                                      const std::string& pathOverride)
{
    ProjectTargetVerification verification;
    if (project.target.kind == ProjectTargetKind::LiveProcess)
    {
        verification.status = ProjectTargetVerificationStatus::NotApplicable;
        return verification;
    }
    const std::string& path = pathOverride.empty() ? project.target.path : pathOverride;
    if (path.empty())
    {
        verification.status = ProjectTargetVerificationStatus::Missing;
        verification.error = "Project target path is empty";
        return verification;
    }
    const std::wstring widePath = Widen(path);
    const DWORD attributes = widePath.empty() ? INVALID_FILE_ATTRIBUTES : GetFileAttributesW(widePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        verification.status = ProjectTargetVerificationStatus::Missing;
        verification.error = "Project target file is missing";
        return verification;
    }
    if (!ComputeFileSha256(path, verification.actualSha256, verification.error))
    {
        verification.status = ProjectTargetVerificationStatus::Unreadable;
        return verification;
    }
    verification.status = EqualDigest(project.target.sha256, verification.actualSha256)
        ? ProjectTargetVerificationStatus::Match
        : ProjectTargetVerificationStatus::HashMismatch;
    if (verification.status == ProjectTargetVerificationStatus::HashMismatch)
        verification.error = "Project target SHA-256 does not match the saved identity";
    return verification;
}

} // namespace openreverse
