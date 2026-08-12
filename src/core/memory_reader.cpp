#include "memory_reader.h"
#include <fstream>
#include <algorithm>
#include <limits>
#include <utility>

namespace openreverse {

void MemoryReader::SetOfflineBuffer(const std::vector<uint8_t>* buffer, uint64_t imageBase)
{
    offlineBuffer_ = buffer;
    offlineImageBase_ = imageBase;
    regions_.clear();

    if (buffer && !buffer->empty())
    {
        regions_.push_back({imageBase, static_cast<uint64_t>(buffer->size()),
                            MEM_COMMIT, PAGE_READONLY, MEM_IMAGE});
    }
}

void MemoryReader::RefreshRegions(HANDLE processHandle)
{
    regions_.clear();
    if (!processHandle)
        return;

    MEMORY_BASIC_INFORMATION mbi;
    uint64_t address = 0;

    while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi)))
    {
        MemoryRegion region;
        region.baseAddress = (uint64_t)mbi.BaseAddress;
        region.size        = mbi.RegionSize;
        region.state       = mbi.State;
        region.protect     = mbi.Protect;
        region.type        = mbi.Type;

        regions_.push_back(region);

        address = (uint64_t)mbi.BaseAddress + mbi.RegionSize;

        // Guard against overflow
        if (address < (uint64_t)mbi.BaseAddress)
            break;
    }
}

std::vector<MemoryRegion> MemoryReader::GetCommittedRegions() const
{
    std::vector<MemoryRegion> result;
    for (const auto& r : regions_)
    {
        if (r.state == MEM_COMMIT)
            result.push_back(r);
    }
    return result;
}

bool MemoryReader::ReadMemory(HANDLE processHandle, uint64_t address, void* buffer, size_t size)
{
    if (!buffer && size != 0)
        return false;

    if (offlineBuffer_ && !offlineBuffer_->empty())
    {
        if (address < offlineImageBase_)
            return false;
        uint64_t offset = address - offlineImageBase_;
        if (offset > offlineBuffer_->size() || size > offlineBuffer_->size() - static_cast<size_t>(offset))
            return false;
        if (size != 0)
            memcpy(buffer, offlineBuffer_->data() + offset, size);
        return true;
    }
    if (!processHandle)
        return false;
    SIZE_T bytesRead = 0;
    BOOL ok = ReadProcessMemory(processHandle, (LPCVOID)address, buffer, size, &bytesRead);
    return ok && bytesRead == size;
}

std::vector<uint8_t> MemoryReader::ReadBytes(HANDLE processHandle, uint64_t address, size_t size)
{
    if (offlineBuffer_ && !offlineBuffer_->empty())
    {
        if (address < offlineImageBase_)
            return {};
        uint64_t offset = address - offlineImageBase_;
        if (offset < offlineBuffer_->size())
        {
            size_t avail = std::min(size, offlineBuffer_->size() - (size_t)offset);
            std::vector<uint8_t> data(avail);
            memcpy(data.data(), offlineBuffer_->data() + offset, avail);
            return data;
        }
        return {};
    }
    if (!processHandle || size == 0)
        return {};
    std::vector<uint8_t> data(size, 0);
    SIZE_T bytesRead = 0;
    ReadProcessMemory(processHandle, (LPCVOID)address, data.data(), size, &bytesRead);
    data.resize(bytesRead);
    return data;
}

MemoryReadReport MemoryReader::ReadReadableBlocks(HANDLE processHandle, uint64_t startAddress,
                                                   uint64_t size, size_t maxBytes)
{
    MemoryReadReport report;
    if (size == 0 || maxBytes == 0 || size > (std::numeric_limits<uint64_t>::max)() - startAddress)
        return report;

    const uint64_t endAddress = startAddress + size;
    if (offlineBuffer_ && !offlineBuffer_->empty())
    {
        if (startAddress < offlineImageBase_)
        {
            report.sourceUnavailable = true;
            return report;
        }
        const uint64_t offset = startAddress - offlineImageBase_;
        if (offset >= offlineBuffer_->size())
        {
            report.sourceUnavailable = true;
            return report;
        }
        const size_t available = std::min<size_t>({static_cast<size_t>(size), maxBytes,
                                                   offlineBuffer_->size() - static_cast<size_t>(offset)});
        MemoryBlock block;
        block.baseAddress = startAddress;
        block.bytes.assign(offlineBuffer_->begin() + static_cast<size_t>(offset),
                           offlineBuffer_->begin() + static_cast<size_t>(offset) + available);
        report.bytesRead = available;
        report.budgetExhausted = available < size && available == maxBytes;
        report.blocks.push_back(std::move(block));
        return report;
    }

    if (!processHandle)
    {
        report.sourceUnavailable = true;
        return report;
    }

    constexpr size_t kReadChunkSize = 64 * 1024;
    uint64_t cursor = startAddress;
    while (cursor < endAddress && report.bytesRead < maxBytes)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) == 0)
        {
            report.sourceUnavailable = true;
            break;
        }

        const uint64_t regionBase = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        if (mbi.RegionSize > (std::numeric_limits<uint64_t>::max)() - regionBase)
            break;
        const uint64_t regionEnd = regionBase + mbi.RegionSize;
        const uint64_t readStart = std::max(cursor, regionBase);
        const uint64_t readEnd = std::min(endAddress, regionEnd);
        if (readEnd <= readStart)
            break;

        const bool readable = mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 &&
            (mbi.Protect & PAGE_NOACCESS) == 0;
        uint64_t readCursor = readStart;
        if (readable)
        {
            while (readCursor < readEnd && report.bytesRead < maxBytes)
            {
                const size_t requested = std::min<size_t>({kReadChunkSize,
                    static_cast<size_t>(readEnd - readCursor), maxBytes - report.bytesRead});
                std::vector<uint8_t> chunk(requested);
                SIZE_T actual = 0;
                if (ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(readCursor),
                                      chunk.data(), requested, &actual) && actual > 0)
                {
                    chunk.resize(actual);
                    if (!report.blocks.empty() &&
                        report.blocks.back().baseAddress + report.blocks.back().bytes.size() == readCursor)
                    {
                        auto& destination = report.blocks.back().bytes;
                        destination.insert(destination.end(), chunk.begin(), chunk.end());
                    }
                    else
                    {
                        report.blocks.push_back({readCursor, std::move(chunk)});
                    }
                    report.bytesRead += actual;
                }

                // Always advance by the attempted range so a changing page cannot stall the walk.
                readCursor += requested;
            }
        }

        cursor = readEnd;
    }

    report.budgetExhausted = report.bytesRead >= maxBytes && cursor < endAddress;
    return report;
}

bool MemoryReader::WriteMemory(HANDLE processHandle, uint64_t address, const void* buffer, size_t size)
{
    SIZE_T bytesWritten = 0;
    BOOL ok = WriteProcessMemory(processHandle, (LPVOID)address, buffer, size, &bytesWritten);
    return ok && bytesWritten == size;
}

size_t MemoryReader::DumpToFile(HANDLE processHandle, uint64_t address, size_t size, const char* filePath)
{
    if ((!processHandle && !offlineBuffer_) || !filePath || size == 0)
        return 0;
    std::vector<uint8_t> data = ReadBytes(processHandle, address, size);
    if (data.empty())
        return 0;
    std::ofstream out(filePath, std::ios::binary);
    if (!out)
        return 0;
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!out)
        return 0;
    return data.size();
}

} // namespace openreverse
