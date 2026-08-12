#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

namespace openreverse {

enum class StringEncoding { ASCII, Unicode };

struct StringResult {
    uint64_t        address;
    std::string     value;
    StringEncoding  encoding;
    size_t          length;
    std::string     category = "General";
};

class StringScanner {
public:
    std::vector<StringResult> Scan(HANDLE processHandle,
                                    uint64_t startAddress, uint64_t endAddress,
                                    size_t minLength = 4,
                                    bool scanAscii = true, bool scanUnicode = true,
                                    size_t maxResults = 5000);

    std::vector<StringResult> ScanBuffer(const uint8_t* data, size_t dataSize, uint64_t baseAddr,
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

} // namespace openreverse
