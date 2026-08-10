#pragma once
// ============================================================================
// OpenReverse - Core: Pattern Scanner
// AOB (Array of Bytes) scanner with wildcard support
// ============================================================================

#include <windows.h>
#include <atomic>
#include <functional>
#include <vector>
#include <string>
#include <cstdint>
#include "core/pe_parser.h"
#include "core/cancellation.h"

namespace openreverse {

struct ScanResult {
    uint64_t address = 0;
    uint32_t rva = 0;
    size_t rawOffset = 0;
    bool hasRva = false;
    bool hasRawOffset = false;
    std::string sectionName;
    std::string patternIdentifier;
};

struct PatternByte {
    uint8_t value;
    bool    wildcard; // true = '??' = match anything
};

enum class OfflinePatternScanScope {
    ExecutableSections,
    AllMappedRegions,
    SpecificSection
};

struct OfflinePatternScanOptions {
    OfflinePatternScanScope scope = OfflinePatternScanScope::ExecutableSections;
    std::string sectionName;
    std::string patternIdentifier;
    size_t maxResults = 1000;
    size_t maxBytes = 64ULL * 1024ULL * 1024ULL;
};

struct PatternScanReport {
    std::vector<ScanResult> results;
    size_t bytesScanned = 0;
    bool resultLimitReached = false;
    bool byteLimitReached = false;
    std::string error;
};

class PatternScanner {
public:
    // Parse pattern string like "48 8B ?? ?? 74 0A" into bytes + mask
    static std::vector<PatternByte> ParsePattern(const std::string& pattern);

    // Scan a validated mapped PE image without confusing RVA and raw offsets.
    PatternScanReport ScanOffline(const std::vector<PatternByte>& pattern,
                                  const std::vector<uint8_t>& mappedImage,
                                  const PEInfo& peInfo,
                                  size_t rawFileSize,
                                  const OfflinePatternScanOptions& options = {},
                                  const CancellationToken* cancellation = nullptr,
                                  const std::function<void(float)>& progress = {});

    // Scan memory for pattern, returns list of matching addresses
    std::vector<ScanResult> Scan(HANDLE processHandle,
                                   const std::vector<PatternByte>& pattern,
                                   uint64_t startAddress, uint64_t endAddress,
                                   size_t maxResults = 1000,
                                   const CancellationToken* cancellation = nullptr);

    // Scan within specific regions
    std::vector<ScanResult> ScanRegions(HANDLE processHandle,
                                         const std::vector<PatternByte>& pattern,
                                         const std::vector<struct MemoryRegion>& regions,
                                         size_t maxResults = 1000,
                                         const CancellationToken* cancellation = nullptr,
                                         const std::function<void(float)>& progress = {});

    // Scan progress (0.0 - 1.0)
    float GetProgress() const { return progress_.load(std::memory_order_relaxed); }
    bool  IsScanning() const { return scanning_.load(std::memory_order_relaxed); }
    void  StopScan() { stopRequested_.store(true, std::memory_order_relaxed); }

private:
    std::atomic<float> progress_{0.0f};
    std::atomic<bool> scanning_{false};
    std::atomic<bool> stopRequested_{false};

    bool MatchPattern(const uint8_t* data, size_t dataSize,
                      const std::vector<PatternByte>& pattern);
};

} // namespace openreverse
