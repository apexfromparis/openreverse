#pragma once
#include "core/pe_parser.h"
namespace kyv { class Application; namespace panels {
class PEViewerPanel {
public:
    void Render(Application& app);
private:
    PEInfo peInfo_;
    bool loaded_ = false;
    uint64_t loadedBase_ = 0;
};
}} // namespace
