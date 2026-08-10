#pragma once
#include <vector>
#include <string>
#include "core/module_manager.h"
namespace openreverse { class Application; namespace panels {
class ModulesPanel {
public:
    void Render(Application& app);
    void Reset();
private:
    int selectedModule_ = -1;
    char filterText_[128] = {};
    std::vector<ExportInfo> cachedExports_;
    bool showExports_ = false;
};
}} // namespace
