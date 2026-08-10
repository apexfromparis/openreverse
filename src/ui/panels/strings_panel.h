#pragma once
#include <vector>
#include <cstdint>
#include "core/string_scanner.h"
namespace openreverse { class Application; namespace panels {
class StringsPanel {
public:
    void Render(Application& app);
private:
    std::vector<StringResult> results_;
    int minLength_ = 4;
    bool scanAscii_ = true;
    bool scanUnicode_ = true;
    char filterText_[256] = {};
    uint64_t targetGeneration_ = 0;
    uint64_t analysisRevision_ = 0;
};
}} // namespace
