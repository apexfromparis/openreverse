#pragma once

#include "core/data_analyzer.h"
#include "core/offset_model.h"
#include "core/version_intelligence.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace openreverse {

constexpr uint32_t kOpenReverseProjectVersion = 1;

enum class ProjectTargetKind {
    PEFile,
    MappedDump,
    RawDump,
    MinidumpModule,
    LiveProcess
};

struct ProjectTarget {
    ProjectTargetKind kind = ProjectTargetKind::PEFile;
    std::string path;
    std::string sha256;
    std::string architecture;
    uint64_t imageBase = 0;
    uint64_t moduleSize = 0;
    uint64_t selectedModuleBase = 0;
    ModuleIdentity module;
};

struct ProjectFunctionAnnotation {
    uint64_t rva = 0;
    std::string name;
    std::string comment;
};

struct ProjectBookmark {
    uint64_t rva = 0;
    std::string label;
    std::string comment;
    uint32_t color = 0;
};

struct ProjectStructureField {
    int64_t offset = 0;
    uint8_t size = 0;
    size_t readCount = 0;
    size_t writeCount = 0;
    size_t addressCount = 0;
    std::string name;
    std::string type;
    std::string comment;
};

struct ProjectStructure {
    std::string stableId;
    std::string name;
    uint64_t sourceFunctionRva = 0;
    std::string baseRegister;
    uint8_t argumentIndex = 0;
    uint64_t estimatedSize = 0;
    uint32_t evidenceScore = 0;
    EvidenceLevel evidence = EvidenceLevel::Unknown;
    bool accepted = false;
    std::vector<ProjectStructureField> fields;
};

enum class ProjectMigrationDecisionKind {
    Accepted,
    Rejected
};

struct ProjectMigrationDecision {
    std::string stableId;
    OffsetKind kind = OffsetKind::UserDefined;
    uint64_t oldRva = 0;
    uint64_t newRva = 0;
    int64_t oldValue = 0;
    int64_t newValue = 0;
    ProjectMigrationDecisionKind decision = ProjectMigrationDecisionKind::Accepted;
    std::vector<std::string> evidence;
};

struct ProjectAnalysisState {
    std::vector<OffsetRecord> offsets;
    std::vector<SignatureRecord> signatures;
    std::vector<ProjectStructure> structures;
};

struct ProjectUserState {
    std::vector<ProjectFunctionAnnotation> functions;
    std::vector<ProjectBookmark> bookmarks;
    std::vector<ProjectStructure> structures;
    std::vector<ProjectMigrationDecision> migrations;
    std::map<std::string, std::string> settings;
};

struct ProjectUiState {
    uint64_t currentRva = 0;
    std::string workspace = "reverse";
    std::vector<std::string> openPanels;
};

struct OpenReverseProject {
    uint32_t version = kOpenReverseProjectVersion;
    ProjectTarget target;
    ProjectAnalysisState analysis;
    ProjectUserState user;
    ProjectUiState ui;
    std::map<std::string, std::string> extensionState;
    bool hasVersionComparison = false;
    VersionComparison versionComparison;
};

enum class ProjectTargetVerificationStatus {
    Match,
    Missing,
    HashMismatch,
    Unreadable,
    NotApplicable
};

struct ProjectTargetVerification {
    ProjectTargetVerificationStatus status = ProjectTargetVerificationStatus::Unreadable;
    std::string actualSha256;
    std::string error;
};

class ProjectStore {
public:
    static bool Serialize(const OpenReverseProject& project, std::string& jsonText,
                          std::string& error);
    static bool Parse(const std::string& jsonText, OpenReverseProject& project,
                      std::string& error);
    static bool SaveAtomic(const std::string& path, const OpenReverseProject& project,
                           std::string& error);
    static bool Load(const std::string& path, OpenReverseProject& project,
                     std::string& error);
    static ProjectTargetVerification VerifyTarget(const OpenReverseProject& project,
                                                   const std::string& pathOverride = {});
    static bool ComputeFileSha256(const std::string& path, std::string& sha256,
                                  std::string& error);
    static bool ValidateExtensionState(const std::string& extensionId,
                                       const std::string& jsonObject,
                                       std::string& canonicalJson,
                                       std::string& error);
};

} // namespace openreverse
