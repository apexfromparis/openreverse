#include "pattern_scanner.h"
#include "memory_reader.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <set>
#include <utility>

namespace openreverse {

std::vector<PatternByte> PatternScanner::ParsePattern(const std::string& pattern)
{
    std::vector<PatternByte> result;
    std::istringstream iss(pattern);
    std::string token;

    while (iss >> token)
    {
        if (result.size() >= 4096)
            return {};
        PatternByte pb{};
        if (token == "?" || token == "??" || token == "**")
        {
            pb.value = 0;
            pb.wildcard = true;
        }
        else
        {
            if (token.size() != 2 || !std::isxdigit(static_cast<unsigned char>(token[0])) ||
                !std::isxdigit(static_cast<unsigned char>(token[1])))
            {
                return {};
            }
            char* end = nullptr;
            const unsigned long value = strtoul(token.c_str(), &end, 16);
            if (!end || *end != '\0' || value > 0xFF)
                return {};
            pb.value = static_cast<uint8_t>(value);
            pb.wildcard = false;
        }
        result.push_back(pb);
    }

    return result;
}

PatternScanReport PatternScanner::ScanOffline(const std::vector<PatternByte>& pattern,
                                               const std::vector<uint8_t>& mappedImage,
                                               const PEInfo& peInfo, size_t rawFileSize,
                                               const OfflinePatternScanOptions& options,
                                               const CancellationToken* cancellation,
                                               const std::function<void(float)>& progress)
{
    PatternScanReport report;
    if (pattern.empty())
    {
        report.error = "Pattern is empty or invalid";
        return report;
    }
    if (pattern.size() > 4096)
    {
        report.error = "Pattern exceeds the 4096-byte safety limit";
        return report;
    }
    if (!peInfo.valid || mappedImage.empty() || mappedImage.size() < peInfo.sizeOfImage)
    {
        report.error = "No valid mapped PE image is available";
        return report;
    }
    if (options.maxResults == 0 || options.maxBytes == 0)
    {
        report.error = "Scan limits must be greater than zero";
        return report;
    }

    struct Range {
        uint32_t rva = 0;
        size_t size = 0;
        std::string section;
    };
    std::vector<Range> ranges;

    if (options.scope == OfflinePatternScanScope::AllMappedRegions && peInfo.sizeOfHeaders != 0)
    {
        ranges.push_back({0, std::min<size_t>(peInfo.sizeOfHeaders, mappedImage.size()), "<headers>"});
    }
    for (const auto& section : peInfo.sections)
    {
        if (options.scope == OfflinePatternScanScope::ExecutableSections &&
            (section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;
        if (options.scope == OfflinePatternScanScope::SpecificSection &&
            options.sectionName != section.name)
            continue;

        const uint64_t requestedSize = options.scope == OfflinePatternScanScope::AllMappedRegions
            ? std::max<uint64_t>(section.virtualSize, section.rawDataSize)
            : section.rawDataSize;
        if (requestedSize == 0 || section.virtualAddress >= mappedImage.size())
            continue;
        const size_t rangeSize = static_cast<size_t>(std::min<uint64_t>(
            requestedSize, mappedImage.size() - section.virtualAddress));
        ranges.push_back({section.virtualAddress, rangeSize, section.name});
    }

    if (options.scope == OfflinePatternScanScope::SpecificSection && ranges.empty())
    {
        report.error = "Requested PE section was not found or has no initialized data";
        return report;
    }

    std::set<uint64_t> uniqueAddresses;
    size_t rangeIndex = 0;
    bool cancelled = false;
    for (const auto& range : ranges)
    {
        if (cancellation && cancellation->IsCancellationRequested())
        {
            cancelled = true;
            break;
        }
        if (report.results.size() >= options.maxResults || report.bytesScanned >= options.maxBytes)
            break;
        const size_t budget = options.maxBytes - report.bytesScanned;
        const size_t scanSize = std::min(range.size, budget);
        if (pattern.size() > scanSize)
        {
            report.bytesScanned += scanSize;
            continue;
        }

        const uint8_t* data = mappedImage.data() + range.rva;
        size_t examinedBytes = 0;
        for (size_t offset = 0; offset <= scanSize - pattern.size(); ++offset)
        {
            if (cancellation && cancellation->IsCancellationRequested())
            {
                cancelled = true;
                break;
            }
            examinedBytes = offset + pattern.size();
            if (!MatchPattern(data + offset, scanSize - offset, pattern))
                continue;
            const uint64_t rva64 = static_cast<uint64_t>(range.rva) + offset;
            if (rva64 > (std::numeric_limits<uint32_t>::max)() ||
                rva64 > (std::numeric_limits<uint64_t>::max)() - peInfo.imageBase ||
                !uniqueAddresses.insert(peInfo.imageBase + rva64).second)
                continue;

            ScanResult result;
            result.address = peInfo.imageBase + rva64;
            result.rva = static_cast<uint32_t>(rva64);
            result.hasRva = true;
            result.sectionName = range.section;
            result.patternIdentifier = options.patternIdentifier;
            size_t rawOffset = 0;
            if (PEParser::RvaToFileOffset(result.rva, pattern.size(), peInfo, rawFileSize, rawOffset))
            {
                result.rawOffset = rawOffset;
                result.hasRawOffset = true;
            }
            report.results.push_back(std::move(result));
            if (report.results.size() >= options.maxResults)
            {
                report.resultLimitReached = true;
                break;
            }
        }
        report.bytesScanned += examinedBytes;
        if (cancelled) break;
        ++rangeIndex;
        if (progress && !ranges.empty()) progress(static_cast<float>(rangeIndex) / ranges.size());
    }

    size_t totalRangeBytes = 0;
    for (const auto& range : ranges)
    {
        if (range.size > (std::numeric_limits<size_t>::max)() - totalRangeBytes)
        {
            totalRangeBytes = (std::numeric_limits<size_t>::max)();
            break;
        }
        totalRangeBytes += range.size;
    }
    report.byteLimitReached = report.bytesScanned < totalRangeBytes && report.bytesScanned >= options.maxBytes;
    return report;
}

bool PatternScanner::MatchPattern(const uint8_t* data, size_t dataSize,
                                   const std::vector<PatternByte>& pattern)
{
    if (dataSize < pattern.size())
        return false;

    for (size_t i = 0; i < pattern.size(); ++i)
    {
        if (!pattern[i].wildcard && data[i] != pattern[i].value)
            return false;
    }
    return true;
}

size_t PatternScanner::AdvanceAfterRead(size_t bytesRead, size_t patternSize)
{
    if (bytesRead == 0 || patternSize == 0)
        return 0;
    if (bytesRead < patternSize)
        return bytesRead;
    return bytesRead - patternSize + 1;
}

std::vector<ScanResult> PatternScanner::Scan(HANDLE processHandle,
                                               const std::vector<PatternByte>& pattern,
                                               uint64_t startAddress, uint64_t endAddress,
                                               size_t maxResults,
                                               const CancellationToken* cancellation)
{
    std::vector<ScanResult> results;
    scanning_ = true;
    stopRequested_ = false;
    progress_ = 0.0f;

    if (!processHandle || pattern.empty() || pattern.size() > 4096 ||
        startAddress >= endAddress || maxResults == 0)
    {
        scanning_ = false;
        return results;
    }

    const size_t chunkSize = (std::max)(static_cast<size_t>(64 * 1024), pattern.size());
    std::vector<uint8_t> buffer(chunkSize);
    uint64_t totalRange = endAddress - startAddress;

    MEMORY_BASIC_INFORMATION mbi;
    uint64_t addr = startAddress;

    while (addr < endAddress && !stopRequested_.load(std::memory_order_relaxed) &&
           (!cancellation || !cancellation->IsCancellationRequested()) && results.size() < maxResults)
    {
        if (!VirtualQueryEx(processHandle, (LPCVOID)addr, &mbi, sizeof(mbi)))
            break;

        uint64_t regionBase = (uint64_t)mbi.BaseAddress;
        if (mbi.RegionSize > (std::numeric_limits<uint64_t>::max)() - regionBase)
            break;
        uint64_t regionEnd = (std::min)(regionBase + mbi.RegionSize, endAddress);

        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 &&
            mbi.Protect != PAGE_NOACCESS)
        {
            uint64_t scanAddr = (std::max)(addr, regionBase);
            while (scanAddr < regionEnd && !stopRequested_.load(std::memory_order_relaxed) &&
                   (!cancellation || !cancellation->IsCancellationRequested()) && results.size() < maxResults)
            {
                size_t bytesToRead = (size_t)(std::min)((uint64_t)chunkSize, regionEnd - scanAddr);
                SIZE_T bytesRead = 0;

                ReadProcessMemory(processHandle, (LPCVOID)scanAddr, buffer.data(), bytesToRead, &bytesRead);
                if (bytesRead > 0)
                {
                    for (size_t i = 0; i + pattern.size() <= bytesRead; ++i)
                    {
                        if (MatchPattern(buffer.data() + i, bytesRead - i, pattern))
                        {
                            results.push_back({ scanAddr + i });
                            if (results.size() >= maxResults)
                                break;
                        }
                    }
                }

                const size_t step = AdvanceAfterRead(bytesRead, pattern.size());
                if (step == 0 || step > (std::numeric_limits<uint64_t>::max)() - scanAddr)
                    break;
                scanAddr += step;
            }
        }

        if (regionEnd <= addr)
            break;
        addr = regionEnd;
        if (totalRange > 0)
            progress_ = (float)(addr - startAddress) / (float)totalRange;
    }

    if (!stopRequested_.load(std::memory_order_relaxed) &&
        (!cancellation || !cancellation->IsCancellationRequested()))
        progress_ = 1.0f;
    scanning_ = false;
    return results;
}

std::vector<ScanResult> PatternScanner::ScanRegions(HANDLE processHandle,
                                                       const std::vector<PatternByte>& pattern,
                                                       const std::vector<MemoryRegion>& regions,
                                                       size_t maxResults,
                                                       const CancellationToken* cancellation,
                                                       const std::function<void(float)>& progress)
{
    std::vector<ScanResult> results;
    scanning_ = true;
    stopRequested_ = false;
    progress_ = 0.0f;

    size_t totalRegions = regions.size();

    for (size_t ri = 0; ri < totalRegions && !stopRequested_.load(std::memory_order_relaxed) &&
         (!cancellation || !cancellation->IsCancellationRequested()) && results.size() < maxResults; ++ri)
    {
        const auto& region = regions[ri];
        if (region.state != MEM_COMMIT || region.size > (std::numeric_limits<uint64_t>::max)() - region.baseAddress)
            continue;

        PatternScanner rangeScanner;
        auto partial = rangeScanner.Scan(processHandle, pattern,
                                         region.baseAddress, region.baseAddress + region.size,
                                         maxResults - results.size(), cancellation);

        results.insert(results.end(), partial.begin(), partial.end());
        progress_ = (float)(ri + 1) / (float)totalRegions;
        if (progress && totalRegions != 0) progress(static_cast<float>(ri + 1) / totalRegions);
    }

    if (!stopRequested_.load(std::memory_order_relaxed) &&
        (!cancellation || !cancellation->IsCancellationRequested()))
        progress_ = 1.0f;
    scanning_ = false;
    return results;
}

} // namespace openreverse
