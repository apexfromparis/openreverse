#pragma once

#include "core/offset_model.h"

#include <cstdint>
#include <string>
#include <vector>

namespace openreverse { class Application; struct ModuleInfo; struct ModuleAnalysisState;

namespace panels {

struct MigrationDisplayRow {
    std::string stableId;
    uint64_t oldTarget = 0;
    uint64_t candidateAddress = 0;
    int64_t candidateValue = 0;
    size_t matchCount = 0;
    SignatureStatus status = SignatureStatus::Invalid;
    SignatureTargetKind targetKind = SignatureTargetKind::MatchAddress;
};

class OffsetsPanel {
public:
    void Render(Application& app);
    void AddFromAddress(Application& app, uint64_t address, const std::string& defaultName = "");

private:
    OffsetProject importedProject_;
    std::string importStatus_;
    uint64_t importRevision_ = 0;
    uint64_t migrationAnalysisRevision_ = 0;
    uint64_t migrationImportRevision_ = 0;
    std::vector<MigrationDisplayRow> migrationRows_;

    void CopyJson(const ModuleAnalysisState& analysis) const;
    void SaveJson(const ModuleAnalysisState& analysis);
    void CopyHeader(const ModuleAnalysisState& analysis) const;
    void ImportJson();
    void RebuildMigration(Application& app, const ModuleAnalysisState& analysis);
};

}} // namespace openreverse::panels
