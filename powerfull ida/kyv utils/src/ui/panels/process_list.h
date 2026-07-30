#pragma once
// ============================================================================
// KYV - UI Panel: Process List
// Browse and attach to running processes
// ============================================================================

#include <string>
#include <vector>
#include "core/process_manager.h"

namespace kyv {
class Application;

namespace panels {

class ProcessListPanel {
public:
    void Render(Application& app);
    void ForceRefresh() { needsRefresh_ = true; }

private:
    char filterText_[256] = {};
    int  selectedIdx_ = -1;
    bool needsRefresh_ = true;
    std::vector<kyv::ProcessInfo> cachedProcesses_;
};

}} // namespace kyv::panels
