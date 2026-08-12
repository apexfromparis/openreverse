#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace openreverse { class Application; struct ModuleInfo;

namespace panels {

struct SavedOffset {
    std::string name;
    uint64_t    address = 0;
    std::string moduleName;
    uint64_t    moduleBase = 0;
    std::string comment;
};

class OffsetsPanel {
public:
    void Render(Application& app);

    void AddFromAddress(Application& app, uint64_t address, const std::string& defaultName = "");

private:
    std::vector<SavedOffset> offsets_;
    char dumpSizeInput_[32] = "1000";
    int  selectedRow_ = -1;

    void ExportTxt();
    void ExportHeader();
    void ExportJson();
};

}} // namespace openreverse::panels
