#pragma once
#include <cstdint>
#include <vector>
#include "core/disassembler.h"

namespace openreverse {
class Application;

namespace panels {

class DisasmViewPanel {
public:
    void Render(Application& app);
    void SetAddress(uint64_t address);
    void Reset();

private:
    uint64_t currentAddress_ = 0;
    char     addressInput_[64] = "0";
    int      numInstructions_ = 50;
    std::vector<Instruction> instructions_;
    bool     needsRefresh_ = true;
    std::vector<uint64_t> history_;

    void RefreshDisassembly(Application& app);
};

}} // namespace openreverse::panels
