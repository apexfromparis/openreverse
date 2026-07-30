#pragma once
#include <vector>
#include <string>
#include "core/pattern_scanner.h"
namespace kyv { class Application; namespace panels {
class ScannerPanel {
public:
    void Render(Application& app);
private:
    char patternInput_[512] = {};
    std::vector<ScanResult> results_;
    bool scanning_ = false;
};
}} // namespace
