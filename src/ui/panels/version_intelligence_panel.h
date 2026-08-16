#pragma once

#include "core/version_intelligence.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace openreverse {
class Application;

namespace panels {

class VersionIntelligencePanel {
public:
    void Render(Application& app, bool* open);

private:
    std::string oldPath_;
    std::string status_;
    VersionAnalysisTarget oldAnalysis_;
    uint64_t jobId_ = 0;
    int selectedFunction_ = -1;
    int selectedCandidate_ = 0;
    int selectedMigration_ = -1;

    void SelectOldTarget();
    void StartComparison(Application& app);
    void RenderSummary(const VersionComparison& comparison) const;
    void RenderFunctions(Application& app, const VersionComparison& comparison);
    void RenderMigrations(Application& app, const VersionComparison& comparison,
                          VersionMigrationKind kind);
    void ApplyDecision(Application& app, const std::string& stableId, VersionDecision decision,
                       uint64_t selectedNewRva = 0);
};

} // namespace panels
} // namespace openreverse
