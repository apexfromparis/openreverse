#pragma once
#include <cstdint>
#include <vector>

namespace openreverse {
class Application;

namespace panels {

class HexEditorPanel {
public:
    void Render(Application& app);
    void SetAddress(uint64_t address);
    void Reset();

private:
    uint64_t currentAddress_ = 0;
    char     addressInput_[64] = "0";
    int      bytesPerRow_ = 16;
    int      numRows_ = 32;
    std::vector<uint8_t> buffer_;
    bool     needsRefresh_ = true;

    int      selectionStart_ = -1;
    int      selectionEnd_ = -1;

    void RefreshBuffer(Application& app);
    void RenderHexRow(Application& app, int row, uint64_t rowAddr);

    float    CalculateEntropy(const uint8_t* data, size_t len) const;
};

}} // namespace openreverse::panels
