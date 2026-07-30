#pragma once
#include <vector>
#include <string>
#include "core/module_manager.h"
namespace kyv { class Application; namespace panels {
class ModulesPanel {
public:
    void Render(Application& app);
private:
    int selectedModule_ = -1;
    char filterText_[128] = {};
    std::vector<ExportInfo> cachedExports_;
    bool showExports_ = false;
};
}} // namespace
