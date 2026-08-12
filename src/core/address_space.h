#pragma once

#include "core/pe_parser.h"

#include <cstddef>
#include <cstdint>
#include <vector>
#include <windows.h>

namespace openreverse {

enum class AddressSpaceKind {
    PEFile,
    MappedImage,
    Process,
    Dump
};

class AddressSpace {
public:
    virtual ~AddressSpace() = default;
    virtual AddressSpaceKind Kind() const = 0;
    virtual uint64_t ImageBase() const = 0;
    virtual uint64_t Size() const = 0;
    virtual bool ResolveRva(uint32_t rva, size_t requiredSize, size_t& sourceOffset) const = 0;
    virtual bool ReadRva(uint32_t rva, void* destination, size_t size) const = 0;

    bool VaToRva(uint64_t va, uint32_t& rva) const;
    bool ReadVa(uint64_t va, void* destination, size_t size) const;
};

class PEFileAddressSpace final : public AddressSpace {
public:
    PEFileAddressSpace(const std::vector<uint8_t>& bytes, const PEInfo& pe);

    AddressSpaceKind Kind() const override { return AddressSpaceKind::PEFile; }
    uint64_t ImageBase() const override { return pe_.imageBase; }
    uint64_t Size() const override { return pe_.sizeOfImage; }
    bool ResolveRva(uint32_t rva, size_t requiredSize, size_t& sourceOffset) const override;
    bool ReadRva(uint32_t rva, void* destination, size_t size) const override;

private:
    const std::vector<uint8_t>& bytes_;
    const PEInfo& pe_;
};

class MappedImageAddressSpace : public AddressSpace {
public:
    MappedImageAddressSpace(const std::vector<uint8_t>& bytes, uint64_t imageBase,
                            AddressSpaceKind kind = AddressSpaceKind::MappedImage);

    AddressSpaceKind Kind() const override { return kind_; }
    uint64_t ImageBase() const override { return imageBase_; }
    uint64_t Size() const override { return bytes_.size(); }
    bool ResolveRva(uint32_t rva, size_t requiredSize, size_t& sourceOffset) const override;
    bool ReadRva(uint32_t rva, void* destination, size_t size) const override;

protected:
    const std::vector<uint8_t>& bytes_;
    uint64_t imageBase_ = 0;
    AddressSpaceKind kind_ = AddressSpaceKind::MappedImage;
};

class DumpAddressSpace final : public MappedImageAddressSpace {
public:
    DumpAddressSpace(const std::vector<uint8_t>& bytes, uint64_t imageBase)
        : MappedImageAddressSpace(bytes, imageBase, AddressSpaceKind::Dump) {}
};

class ProcessAddressSpace final : public AddressSpace {
public:
    ProcessAddressSpace(HANDLE process, uint64_t imageBase, uint64_t size);

    AddressSpaceKind Kind() const override { return AddressSpaceKind::Process; }
    uint64_t ImageBase() const override { return imageBase_; }
    uint64_t Size() const override { return size_; }
    bool ResolveRva(uint32_t rva, size_t requiredSize, size_t& sourceOffset) const override;
    bool ReadRva(uint32_t rva, void* destination, size_t size) const override;

private:
    HANDLE process_ = nullptr;
    uint64_t imageBase_ = 0;
    uint64_t size_ = 0;
};

} // namespace openreverse
