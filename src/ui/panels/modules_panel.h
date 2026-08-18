#pragma once
#include "analysis/pe_parser.h"

#include <vector>
#include <string>

namespace openreverse { class Application; namespace panels {
class ModulesPanel {
public:
    void Render(Application& app);
    void Reset();
private:
    int selectedModule_ = -1;
    char filterText_[128] = {};
    std::vector<PEInfo::PEExportEntry> cachedExports_;
    bool showExports_ = false;
};
}} // namespace
