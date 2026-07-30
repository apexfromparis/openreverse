#pragma once
#include <vector>
#include <string>
#include <cstdint>
namespace kyv { class Application; namespace panels {

struct Bookmark {
    uint64_t    address;
    std::string label;
    std::string comment;
    uint32_t    color; // ImGui packed color
};

class BookmarksPanel {
public:
    void Render(Application& app);
private:
    std::vector<Bookmark> bookmarks_;
    char labelInput_[128] = {};
    char commentInput_[256] = {};
    char addrInput_[64] = {};
};
}} // namespace
