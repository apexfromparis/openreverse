#pragma once
#include <vector>
#include "core/string_scanner.h"
namespace kyv { class Application; namespace panels {
class StringsPanel {
public:
    void Render(Application& app);
private:
    std::vector<StringResult> results_;
    int minLength_ = 4;
    bool scanAscii_ = true;
    bool scanUnicode_ = true;
    char filterText_[256] = {};
};
}} // namespace
