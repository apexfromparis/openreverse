#pragma once
// OpenReverse - Core: Memory Reader
// Read/write process memory, enumerate memory regions

#include <windows.h>
#include <vector>
#include <cstdint>
#include <string>

namespace openreverse {

struct MemoryRegion {
    uint64_t    baseAddress;
    uint64_t    size;
    DWORD       state;       // MEM_COMMIT, MEM_RESERVE, MEM_FREE
    DWORD       protect;     // PAGE_READWRITE, PAGE_EXECUTE_READ, etc.
    DWORD       type;        // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
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
    // Refresh the memory region map
    void RefreshRegions(HANDLE processHandle);

    // Get cached memory regions
    const std::vector<MemoryRegion>& GetRegions() const { return regions_; }

    // Get only committed regions
    std::vector<MemoryRegion> GetCommittedRegions() const;

    // Read raw bytes from process memory
    bool ReadMemory(HANDLE processHandle, uint64_t address, void* buffer, size_t size);

    // Read as vector<uint8_t>
    std::vector<uint8_t> ReadBytes(HANDLE processHandle, uint64_t address, size_t size);

    // Read only committed/readable portions and preserve their true addresses.
    MemoryReadReport ReadReadableBlocks(HANDLE processHandle, uint64_t startAddress,
                                        uint64_t size, size_t maxBytes);

    // Write bytes to process memory
    bool WriteMemory(HANDLE processHandle, uint64_t address, const void* buffer, size_t size);

    // Dump process memory to file (real read + write to disk). Returns bytes written, 0 on failure.
    size_t DumpToFile(HANDLE processHandle, uint64_t address, size_t size, const char* filePath);

    // Read typed values
    template<typename T>
    T Read(HANDLE processHandle, uint64_t address)
    {
        T value{};
        ReadMemory(processHandle, address, &value, sizeof(T));
        return value;
    }

    // Set a PE image mapped by RVA for static analysis.
    void SetOfflineBuffer(const std::vector<uint8_t>* buffer, uint64_t imageBase);

private:
    std::vector<MemoryRegion> regions_;
    const std::vector<uint8_t>* offlineBuffer_ = nullptr;
    uint64_t offlineImageBase_ = 0;
};

} // namespace openreverse
