#pragma once
// ============================================================================
// OpenReverse - Core: Pattern Scanner
// AOB (Array of Bytes) scanner with wildcard support
// ============================================================================

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

namespace openreverse {

struct ScanResult {
    uint64_t address;
};

struct PatternByte {
    uint8_t value;
    bool    wildcard; // true = '??' = match anything
};

class PatternScanner {
public:
    // Parse pattern string like "48 8B ?? ?? 74 0A" into bytes + mask
    static std::vector<PatternByte> ParsePattern(const std::string& pattern);

    // Scan memory for pattern, returns list of matching addresses
    std::vector<ScanResult> Scan(HANDLE processHandle,
                                  const std::vector<PatternByte>& pattern,
                                  uint64_t startAddress, uint64_t endAddress,
                                  size_t maxResults = 1000);

    // Scan within specific regions
    std::vector<ScanResult> ScanRegions(HANDLE processHandle,
                                         const std::vector<PatternByte>& pattern,
                                         const std::vector<struct MemoryRegion>& regions,
                                         size_t maxResults = 1000);

    // Scan progress (0.0 - 1.0)
    float GetProgress() const { return progress_; }
    bool  IsScanning() const { return scanning_; }
    void  StopScan() { stopRequested_ = true; }

private:
    float progress_ = 0.0f;
    bool  scanning_ = false;
    bool  stopRequested_ = false;

    bool MatchPattern(const uint8_t* data, size_t dataSize,
                      const std::vector<PatternByte>& pattern);
};

} // namespace openreverse
