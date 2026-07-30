#pragma once
// ============================================================================
// KYV - UI Panel: Hex Editor
// Classic hex viewer/editor with address | hex | ASCII columns
// ============================================================================

#include <cstdint>
#include <vector>

namespace kyv {
class Application;

namespace panels {

class HexEditorPanel {
public:
    void Render(Application& app);
    void SetAddress(uint64_t address);

private:
    uint64_t currentAddress_ = 0;
    char     addressInput_[64] = "0";
    int      bytesPerRow_ = 16;
    int      numRows_ = 32;
    std::vector<uint8_t> buffer_;
    bool     needsRefresh_ = true;

    // Selection
    int      selectionStart_ = -1;
    int      selectionEnd_ = -1;

    // Search
    char     searchInput_[256] = {};
    bool     searchHex_ = true;
    int      searchMatchIndex_ = -1;
    std::vector<size_t> searchMatches_;

    void RefreshBuffer(Application& app);
    void RenderHexRow(Application& app, int row, uint64_t rowAddr);
    void DoSearch();
    bool HasSelection() const;
    void CopySelectionHex();
    void CopySelectionCArray();

    // Entropy Heatmap Analysis
    bool     showEntropy_ = true;
    float    CalculateEntropy(const uint8_t* data, size_t len) const;
};

}} // namespace kyv::panels
