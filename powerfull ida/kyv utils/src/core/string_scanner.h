#pragma once
// ============================================================================
// KYV - Core: String Scanner
// Find ASCII and Unicode strings in process memory
// ============================================================================

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

namespace kyv {

enum class StringEncoding { ASCII, Unicode };

struct StringResult {
    uint64_t        address;
    std::string     value;
    StringEncoding  encoding;
    size_t          length;
    std::string     category = "General";
    int             riskLevel = 0; // 0=Normal, 1=Low, 2=Medium, 3=High Risk (C2/Exec)
};

class StringScanner {
public:
    // Scan for strings in memory region
    std::vector<StringResult> Scan(HANDLE processHandle,
                                    uint64_t startAddress, uint64_t endAddress,
                                    size_t minLength = 4,
                                    bool scanAscii = true, bool scanUnicode = true,
                                    size_t maxResults = 5000);

    float GetProgress() const { return progress_; }

private:
    float progress_ = 0.0f;

    void ScanAsciiStrings(const uint8_t* data, size_t dataSize, uint64_t baseAddr,
                           size_t minLength, std::vector<StringResult>& results, size_t maxResults);
    void ScanUnicodeStrings(const uint8_t* data, size_t dataSize, uint64_t baseAddr,
                             size_t minLength, std::vector<StringResult>& results, size_t maxResults);
    bool IsPrintableAscii(uint8_t c);
    void ClassifyString(StringResult& sr);
};

} // namespace kyv
