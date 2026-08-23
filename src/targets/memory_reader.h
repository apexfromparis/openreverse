#pragma once

#include <windows.h>
#include <vector>
#include <cstdint>
#include <string>

namespace openreverse {

struct MemoryRegion {
    uint64_t    baseAddress;
    uint64_t    size;
    DWORD       state;
    DWORD       protect;
    DWORD       type;
};

struct MemoryBlock {
    uint64_t baseAddress = 0;
    std::vector<uint8_t> bytes;
};

struct MemoryReadReport {
    std::vector<MemoryBlock> blocks;
    size_t bytesRead = 0;
    bool budgetExhausted = false;
    bool sourceUnavailable = false;
};

class MemoryReader {
public:
    void RefreshRegions(HANDLE processHandle);

    const std::vector<MemoryRegion>& GetRegions() const { return regions_; }

    std::vector<MemoryRegion> GetCommittedRegions() const;

    bool ReadMemory(HANDLE processHandle, uint64_t address, void* buffer, size_t size);

    std::vector<uint8_t> ReadBytes(HANDLE processHandle, uint64_t address, size_t size);

    // Read only committed/readable portions and preserve their true addresses.
    MemoryReadReport ReadReadableBlocks(HANDLE processHandle, uint64_t startAddress,
                                        uint64_t size, size_t maxBytes);

    size_t DumpToFile(HANDLE processHandle, uint64_t address, size_t size,
                      const std::string& filePath);

    template<typename T>
    T Read(HANDLE processHandle, uint64_t address)
    {
        T value{};
        ReadMemory(processHandle, address, &value, sizeof(T));
        return value;
    }

    void SetOfflineBuffer(const std::vector<uint8_t>* buffer, uint64_t imageBase);

private:
    std::vector<MemoryRegion> regions_;
    const std::vector<uint8_t>* offlineBuffer_ = nullptr;
    uint64_t offlineImageBase_ = 0;
};

} // namespace openreverse
