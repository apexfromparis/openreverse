// ============================================================================
// KYV - Core: Memory Reader Implementation
// ============================================================================

#include "memory_reader.h"
#include <fstream>
#include <algorithm>

namespace kyv {

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
    SIZE_T bytesRead = 0;
    BOOL ok = ReadProcessMemory(processHandle, (LPCVOID)address, buffer, size, &bytesRead);
    return ok && bytesRead == size;
}

std::vector<uint8_t> MemoryReader::ReadBytes(HANDLE processHandle, uint64_t address, size_t size)
{
    std::vector<uint8_t> data(size, 0);
    SIZE_T bytesRead = 0;
    ReadProcessMemory(processHandle, (LPCVOID)address, data.data(), size, &bytesRead);
    data.resize(bytesRead);
    return data;
}

bool MemoryReader::WriteMemory(HANDLE processHandle, uint64_t address, const void* buffer, size_t size)
{
    SIZE_T bytesWritten = 0;
    BOOL ok = WriteProcessMemory(processHandle, (LPVOID)address, buffer, size, &bytesWritten);
    return ok && bytesWritten == size;
}

size_t MemoryReader::DumpToFile(HANDLE processHandle, uint64_t address, size_t size, const char* filePath)
{
    if (!processHandle || !filePath || size == 0)
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

} // namespace kyv
