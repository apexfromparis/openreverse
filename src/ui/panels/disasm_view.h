#pragma once
// ============================================================================
// OpenReverse - UI Panel: Disassembly View
// x86/x64 disassembly listing
// ============================================================================

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

private:
    uint64_t currentAddress_ = 0;
    char     addressInput_[64] = "0";
    int      numInstructions_ = 50;
    std::vector<Instruction> instructions_;
    bool     needsRefresh_ = true;
    bool     intelSyntax_ = true;
    std::vector<uint64_t> history_;
    char     searchFilter_[128] = {};

    void RefreshDisassembly(Application& app);
};

}} // namespace openreverse::panels
