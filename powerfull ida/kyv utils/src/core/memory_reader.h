#pragma once
// ============================================================================
// KYV - Core: Memory Reader
// Read/write process memory, enumerate memory regions
// ============================================================================

#include <windows.h>
#include <vector>
#include <cstdint>
#include <string>

namespace kyv {

struct MemoryRegion {
    uint64_t    baseAddress;
    uint64_t    size;
    DWORD       state;       // MEM_COMMIT, MEM_RESERVE, MEM_FREE
    DWORD       protect;     // PAGE_READWRITE, PAGE_EXECUTE_READ, etc.
    DWORD       type;        // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
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

private:
    std::vector<MemoryRegion> regions_;
};

} // namespace kyv
