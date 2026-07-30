#pragma once
#include <cstdint>
namespace kyv { class Application; namespace panels {
class MemoryMapPanel {
public:
    void Render(Application& app);
private:
    bool showFree_ = false;
    bool needsRefresh_ = false;
    char filterText_[128] = {};
};
}} // namespace
