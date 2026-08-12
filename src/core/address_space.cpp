#include "address_space.h"

#include <cstring>
#include <limits>

namespace openreverse {

namespace {

bool IsRangeValid(uint64_t offset, size_t size, uint64_t total)
{
    return offset <= total && size <= total - offset;
}

} // namespace

bool AddressSpace::VaToRva(uint64_t va, uint32_t& rva) const
{
    rva = 0;
    if (va < ImageBase() || va - ImageBase() >= Size() ||
        va - ImageBase() > (std::numeric_limits<uint32_t>::max)())
        return false;
    rva = static_cast<uint32_t>(va - ImageBase());
    return true;
}

bool AddressSpace::ReadVa(uint64_t va, void* destination, size_t size) const
{
    uint32_t rva = 0;
    return VaToRva(va, rva) && ReadRva(rva, destination, size);
}

PEFileAddressSpace::PEFileAddressSpace(const std::vector<uint8_t>& bytes, const PEInfo& pe)
    : bytes_(bytes), pe_(pe)
{
}

bool PEFileAddressSpace::ResolveRva(uint32_t rva, size_t requiredSize, size_t& sourceOffset) const
{
    return PEParser::RvaToFileOffset(rva, requiredSize, pe_, bytes_.size(), sourceOffset);
}

bool PEFileAddressSpace::ReadRva(uint32_t rva, void* destination, size_t size) const
{
    size_t offset = 0;
    if ((!destination && size != 0) || !ResolveRva(rva, size, offset))
        return false;
    if (size != 0)
        std::memcpy(destination, bytes_.data() + offset, size);
    return true;
}

MappedImageAddressSpace::MappedImageAddressSpace(const std::vector<uint8_t>& bytes,
                                                 uint64_t imageBase, AddressSpaceKind kind)
    : bytes_(bytes), imageBase_(imageBase), kind_(kind)
{
}

bool MappedImageAddressSpace::ResolveRva(uint32_t rva, size_t requiredSize, size_t& sourceOffset) const
{
    sourceOffset = 0;
    if (!IsRangeValid(rva, requiredSize, bytes_.size()))
        return false;
    sourceOffset = rva;
    return true;
}

bool MappedImageAddressSpace::ReadRva(uint32_t rva, void* destination, size_t size) const
{
    size_t offset = 0;
    if ((!destination && size != 0) || !ResolveRva(rva, size, offset))
        return false;
    if (size != 0)
        std::memcpy(destination, bytes_.data() + offset, size);
    return true;
}

ProcessAddressSpace::ProcessAddressSpace(HANDLE process, uint64_t imageBase, uint64_t size)
    : process_(process), imageBase_(imageBase), size_(size)
{
}

bool ProcessAddressSpace::ResolveRva(uint32_t rva, size_t requiredSize, size_t& sourceOffset) const
{
    sourceOffset = 0;
    if (!IsRangeValid(rva, requiredSize, size_))
        return false;
    sourceOffset = rva;
    return true;
}

bool ProcessAddressSpace::ReadRva(uint32_t rva, void* destination, size_t size) const
{
    size_t offset = 0;
    if (!process_ || (!destination && size != 0) || !ResolveRva(rva, size, offset) ||
        imageBase_ > (std::numeric_limits<uint64_t>::max)() - offset)
        return false;
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(process_, reinterpret_cast<LPCVOID>(imageBase_ + offset),
                             destination, size, &bytesRead) && bytesRead == size;
}

} // namespace openreverse
