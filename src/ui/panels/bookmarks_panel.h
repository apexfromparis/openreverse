#pragma once
namespace openreverse { class Application; namespace panels {

class BookmarksPanel {
public:
    void Render(Application& app);
private:
    char labelInput_[128] = {};
    char commentInput_[256] = {};
    char addrInput_[64] = {};
};
}} // namespace
