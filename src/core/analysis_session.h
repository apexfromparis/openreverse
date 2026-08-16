#pragma once

#include "core/analysis_database.h"
#include "core/module_analyzer.h"
#include "core/project.h"

#include <cstddef>
#include <string>

namespace openreverse {

class AnalysisSession {
public:
    AnalysisDatabase& Database() { return database_; }
    const AnalysisDatabase& Database() const { return database_; }

    void ClearAnalysis();
    void ClearProject();
    void SetLoadedProject(OpenReverseProject project, const std::string& path,
                          bool restoreTargetBoundState);
    void MarkSaved(OpenReverseProject project, const std::string& path);

    bool HasProject() const { return hasProject_; }
    bool IsDirty() const { return dirty_; }
    bool RequiresSaveAs() const { return requiresSaveAs_; }
    bool RestoresTargetBoundState() const { return restoreTargetBoundState_; }
    const std::string& ProjectPath() const { return projectPath_; }
    const OpenReverseProject& Project() const { return project_; }
    void MarkDirty();

    OpenReverseProject BuildSnapshot(const ProjectTarget& target,
                                     const ModuleAnalysisState& analysis,
                                     const ProjectUiState& ui) const;
    void ApplyPersistedAnalysis(ModuleAnalysisResult& result) const;

    const ProjectFunctionAnnotation* FindFunctionAnnotation(uint64_t rva) const;
    void SetFunctionAnnotation(uint64_t rva, const std::string& name,
                               const std::string& comment);
    void RemoveFunctionAnnotation(uint64_t rva);

    const std::vector<ProjectBookmark>& Bookmarks() const { return project_.user.bookmarks; }
    void AddBookmark(ProjectBookmark bookmark);
    void RemoveBookmark(size_t index);

    const VersionComparison* VersionIntelligence() const;
    void SetVersionComparison(VersionComparison comparison);
    bool SetVersionDecision(const std::string& stableId, VersionDecision decision,
                            uint64_t selectedNewRva = 0);

    const std::string* ExtensionState(const std::string& extensionId) const;
    bool SetExtensionState(const std::string& extensionId, const std::string& jsonObject,
                           std::string& error);

private:
    AnalysisDatabase database_;
    OpenReverseProject project_;
    std::string projectPath_;
    bool hasProject_ = false;
    bool dirty_ = false;
    bool requiresSaveAs_ = false;
    bool restoreTargetBoundState_ = false;
};

} // namespace openreverse
