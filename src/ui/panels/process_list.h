#pragma once

#include <string>
#include <vector>
#include "targets/process_access.h"

namespace openreverse {
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
    std::vector<openreverse::ProcessInfo> cachedProcesses_;
};

}} // namespace openreverse::panels
