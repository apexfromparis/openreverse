// ============================================================================
// KYV - Core: Pattern Scanner Implementation
// ============================================================================

#include "pattern_scanner.h"
#include "memory_reader.h"
#include <sstream>
#include <algorithm>

namespace kyv {

std::vector<PatternByte> PatternScanner::ParsePattern(const std::string& pattern)
{
    std::vector<PatternByte> result;
    std::istringstream iss(pattern);
    std::string token;

    while (iss >> token)
    {
        PatternByte pb;
        if (token == "?" || token == "??" || token == "**")
        {
            pb.value = 0;
            pb.wildcard = true;
        }
        else
        {
            pb.value = (uint8_t)strtoul(token.c_str(), nullptr, 16);
            pb.wildcard = false;
        }
        result.push_back(pb);
    }

    return result;
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

std::vector<ScanResult> PatternScanner::Scan(HANDLE processHandle,
                                               const std::vector<PatternByte>& pattern,
                                               uint64_t startAddress, uint64_t endAddress,
                                               size_t maxResults)
{
    std::vector<ScanResult> results;
    scanning_ = true;
    stopRequested_ = false;
    progress_ = 0.0f;

    if (pattern.empty())
    {
        scanning_ = false;
        return results;
    }

    const size_t chunkSize = 64 * 1024; // 64KB chunks
    std::vector<uint8_t> buffer(chunkSize);
    uint64_t totalRange = endAddress - startAddress;

    MEMORY_BASIC_INFORMATION mbi;
    uint64_t addr = startAddress;

    while (addr < endAddress && !stopRequested_ && results.size() < maxResults)
    {
        if (!VirtualQueryEx(processHandle, (LPCVOID)addr, &mbi, sizeof(mbi)))
            break;

        uint64_t regionBase = (uint64_t)mbi.BaseAddress;
        uint64_t regionEnd = regionBase + mbi.RegionSize;

        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 &&
            mbi.Protect != PAGE_NOACCESS)
        {
            uint64_t scanAddr = (std::max)(addr, regionBase);
            while (scanAddr < regionEnd && !stopRequested_ && results.size() < maxResults)
            {
                size_t bytesToRead = (size_t)(std::min)((uint64_t)chunkSize, regionEnd - scanAddr);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(processHandle, (LPCVOID)scanAddr, buffer.data(), bytesToRead, &bytesRead))
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

                scanAddr += bytesToRead - pattern.size() + 1;
            }
        }

        addr = regionEnd;
        if (totalRange > 0)
            progress_ = (float)(addr - startAddress) / (float)totalRange;
    }

    progress_ = 1.0f;
    scanning_ = false;
    return results;
}

std::vector<ScanResult> PatternScanner::ScanRegions(HANDLE processHandle,
                                                      const std::vector<PatternByte>& pattern,
                                                      const std::vector<MemoryRegion>& regions,
                                                      size_t maxResults)
{
    std::vector<ScanResult> results;
    scanning_ = true;
    stopRequested_ = false;
    progress_ = 0.0f;

    size_t totalRegions = regions.size();

    for (size_t ri = 0; ri < totalRegions && !stopRequested_ && results.size() < maxResults; ++ri)
    {
        const auto& region = regions[ri];
        if (region.state != MEM_COMMIT)
            continue;

        auto partial = Scan(processHandle, pattern,
                            region.baseAddress, region.baseAddress + region.size,
                            maxResults - results.size());

        results.insert(results.end(), partial.begin(), partial.end());
        progress_ = (float)(ri + 1) / (float)totalRegions;
    }

    progress_ = 1.0f;
    scanning_ = false;
    return results;
}

} // namespace kyv
