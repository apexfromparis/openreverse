#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include "analysis/pattern_scanner.h"
namespace openreverse { class Application; namespace panels {
class ScannerPanel {
public:
    void Render(Application& app);
private:
    char patternInput_[512] = {};
    PatternScanReport report_;
    int selectedPreset_ = 0;
    int offlineScope_ = 0;
    int selectedSection_ = 0;
    uint64_t targetGeneration_ = 0;
    uint64_t scanJobId_ = 0;
};
}} // namespace
