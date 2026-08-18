#pragma once
#include "analysis/pe_parser.h"
namespace openreverse { class Application; namespace panels {
class PEViewerPanel {
public:
    void Render(Application& app);
private:
    PEInfo peInfo_;
    bool loaded_ = false;
    uint64_t loadedBase_ = 0;
    uint64_t targetGeneration_ = 0;
};
}} // namespace
