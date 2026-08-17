#include "dump_loader.h"

#include <DbgHelp.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <limits>

namespace openreverse {

namespace {

constexpr size_t kMaximumDumpSize = 512ULL * 1024ULL * 1024ULL;

std::string FileName(const std::string& path)
{
    const size_t separator = path.find_last_of("/\\");
    return separator == std::string::npos ? path : path.substr(separator + 1);
}

bool ReadFile(const std::string& path, std::vector<uint8_t>& bytes, std::string& error)
{
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream)
    {
        error = "Dump file could not be opened";
        return false;
    }
    const std::streamoff length = stream.tellg();
    if (length <= 0 || static_cast<uint64_t>(length) > kMaximumDumpSize)
    {
        error = "Dump file is empty or exceeds the 512 MB import limit";
        return false;
    }
    bytes.resize(static_cast<size_t>(length));
    stream.seekg(0);
    if (!stream.read(reinterpret_cast<char*>(bytes.data()), length))
    {
        bytes.clear();
        error = "Dump file could not be read completely";
        return false;
    }
    return true;
}

bool IsMinidump(const std::vector<uint8_t>& bytes)
{
    ULONG32 signature = 0;
    if (bytes.size() < sizeof(signature)) return false;
    std::memcpy(&signature, bytes.data(), sizeof(signature));
    return signature == MINIDUMP_SIGNATURE;
}

std::string ReadMinidumpString(const std::vector<uint8_t>& bytes, RVA rva)
{
    if (rva > bytes.size() || sizeof(ULONG32) > bytes.size() - rva) return {};
    ULONG32 byteLength = 0;
    std::memcpy(&byteLength, bytes.data() + rva, sizeof(byteLength));
    const size_t textOffset = static_cast<size_t>(rva) + sizeof(byteLength);
    if (byteLength > bytes.size() - textOffset || byteLength % sizeof(wchar_t) != 0) return {};
    const auto* wide = reinterpret_cast<const wchar_t*>(bytes.data() + textOffset);
    const int wideLength = static_cast<int>(byteLength / sizeof(wchar_t));
    const int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wide, wideLength, nullptr, 0, nullptr, nullptr);
    if (utf8Length <= 0) return {};
    std::string result(static_cast<size_t>(utf8Length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, wideLength, result.data(), utf8Length, nullptr, nullptr);
    return result;
}

bool CopyRange(std::vector<uint8_t>& image, uint64_t moduleBase, uint64_t memoryBase,
               const uint8_t* source, size_t sourceSize, size_t& copied)
{
    const uint64_t moduleEnd = moduleBase + image.size();
    if (moduleEnd < moduleBase || sourceSize > (std::numeric_limits<uint64_t>::max)() - memoryBase)
        return false;
    const uint64_t memoryEnd = memoryBase + sourceSize;
    const uint64_t start = std::max(moduleBase, memoryBase);
    const uint64_t end = std::min(moduleEnd, memoryEnd);
    if (start >= end) return true;
    const size_t destinationOffset = static_cast<size_t>(start - moduleBase);
    const size_t sourceOffset = static_cast<size_t>(start - memoryBase);
    const size_t length = static_cast<size_t>(end - start);
    std::memcpy(image.data() + destinationOffset, source + sourceOffset, length);
    copied += length;
    return true;
}

DumpLoadResult LoadMinidump(const std::string& path, const std::vector<uint8_t>& bytes,
                            const DumpImportOptions& options)
{
    DumpLoadResult result;
    result.representation = DumpRepresentation::Minidump;
    PMINIDUMP_DIRECTORY directory = nullptr;
    PVOID stream = nullptr;
    ULONG streamSize = 0;

    if (MiniDumpReadDumpStream(const_cast<uint8_t*>(bytes.data()), SystemInfoStream,
                               &directory, &stream, &streamSize) &&
        stream != nullptr &&
        streamSize >= sizeof(MINIDUMP_SYSTEM_INFO))
    {
        const auto* system = static_cast<const MINIDUMP_SYSTEM_INFO*>(stream);
        result.architecture = system->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
            ? DumpArchitecture::X64 : system->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL
            ? DumpArchitecture::X86 : DumpArchitecture::Unknown;
    }

    if (!MiniDumpReadDumpStream(const_cast<uint8_t*>(bytes.data()), ModuleListStream,
                                &directory, &stream, &streamSize) ||
        stream == nullptr ||
        streamSize < sizeof(ULONG32))
    {
        result.error = "Minidump does not contain a module list";
        return result;
    }
    const auto* modules = static_cast<const MINIDUMP_MODULE_LIST*>(stream);
    if (modules->NumberOfModules > 100000 ||
        modules->NumberOfModules > (streamSize - offsetof(MINIDUMP_MODULE_LIST, Modules)) /
            sizeof(MINIDUMP_MODULE))
    {
        result.error = "Minidump module list exceeds import limits";
        return result;
    }
    for (ULONG32 index = 0; index < modules->NumberOfModules; ++index)
    {
        const auto& module = modules->Modules[index];
        result.availableModules.push_back({ReadMinidumpString(bytes, module.ModuleNameRva),
            module.BaseOfImage, module.SizeOfImage, module.TimeDateStamp});
    }

    const DumpModuleMetadata* selected = nullptr;
    if (options.minidumpModuleBase != 0)
    {
        const auto found = std::find_if(result.availableModules.begin(), result.availableModules.end(),
            [&](const DumpModuleMetadata& module) { return module.imageBase == options.minidumpModuleBase; });
        if (found != result.availableModules.end()) selected = &*found;
    }
    else if (result.availableModules.size() == 1)
        selected = &result.availableModules.front();
    if (!selected)
    {
        result.error = "Select a module base from the minidump module list";
        return result;
    }
    if (selected->imageSize == 0 || selected->imageSize > kMaximumDumpSize)
    {
        result.error = "Selected minidump module has an invalid size";
        return result;
    }

    result.imageBytes.assign(selected->imageSize, 0);
    size_t copied = 0;
    if (MiniDumpReadDumpStream(const_cast<uint8_t*>(bytes.data()), Memory64ListStream,
                               &directory, &stream, &streamSize) &&
        stream != nullptr &&
        streamSize >= sizeof(MINIDUMP_MEMORY64_LIST))
    {
        const auto* list = static_cast<const MINIDUMP_MEMORY64_LIST*>(stream);
        if (list->NumberOfMemoryRanges >
            (streamSize - offsetof(MINIDUMP_MEMORY64_LIST, MemoryRanges)) /
                sizeof(MINIDUMP_MEMORY_DESCRIPTOR64))
        {
            result.error = "Minidump memory64 list is truncated";
            return result;
        }
        uint64_t dataRva = list->BaseRva;
        for (ULONG64 index = 0; index < list->NumberOfMemoryRanges; ++index)
        {
            const auto& range = list->MemoryRanges[index];
            if (dataRva > bytes.size() || range.DataSize > bytes.size() - dataRva) break;
            CopyRange(result.imageBytes, selected->imageBase, range.StartOfMemoryRange,
                      bytes.data() + static_cast<size_t>(dataRva), static_cast<size_t>(range.DataSize), copied);
            dataRva += range.DataSize;
        }
    }
    if (MiniDumpReadDumpStream(const_cast<uint8_t*>(bytes.data()), MemoryListStream,
                               &directory, &stream, &streamSize) &&
        stream != nullptr &&
        streamSize >= sizeof(MINIDUMP_MEMORY_LIST))
    {
        const auto* list = static_cast<const MINIDUMP_MEMORY_LIST*>(stream);
        if (list->NumberOfMemoryRanges >
            (streamSize - offsetof(MINIDUMP_MEMORY_LIST, MemoryRanges)) /
                sizeof(MINIDUMP_MEMORY_DESCRIPTOR))
        {
            result.error = "Minidump memory list is truncated";
            return result;
        }
        for (ULONG32 index = 0; index < list->NumberOfMemoryRanges; ++index)
        {
            const auto& range = list->MemoryRanges[index];
            const size_t rva = range.Memory.Rva;
            const size_t size = range.Memory.DataSize;
            if (rva > bytes.size() || size > bytes.size() - rva) continue;
            CopyRange(result.imageBytes, selected->imageBase, range.StartOfMemoryRange,
                      bytes.data() + rva, size, copied);
        }
    }
    if (copied == 0)
    {
        result.error = "Selected minidump module has no captured memory ranges";
        result.imageBytes.clear();
        return result;
    }

    PEParser parser;
    result.pe = parser.ParseMappedImage(result.imageBytes.data(), result.imageBytes.size(),
                                        selected->imageBase);
    if (!result.pe.valid)
    {
        result.error = "Selected minidump module does not contain complete mapped PE headers";
        result.imageBytes.clear();
        return result;
    }
    result.module = {FileName(selected->name), path, selected->imageBase, selected->imageSize};
    result.success = true;
    return result;
}

} // namespace

DumpLoadResult DumpLoader::Load(const std::string& path, const DumpImportOptions& options) const
{
    DumpLoadResult result;
    std::vector<uint8_t> bytes;
    if (!ReadFile(path, bytes, result.error)) return result;
    if (IsMinidump(bytes)) return LoadMinidump(path, bytes, options);

    PEParser parser;
    const bool tryMapped = options.representation == DumpRepresentation::AutoDetect ||
                           options.representation == DumpRepresentation::MappedPEImage;
    if (tryMapped)
    {
        PEInfo pe = parser.ParseMappedImage(bytes.data(), bytes.size(), options.imageBase);
        if (pe.valid)
        {
            result.success = true;
            result.representation = DumpRepresentation::MappedPEImage;
            result.architecture = pe.is64bit ? DumpArchitecture::X64 : DumpArchitecture::X86;
            result.pe = std::move(pe);
            result.imageBytes.assign(bytes.begin(), bytes.begin() + result.pe.sizeOfImage);
            result.module = {FileName(path), path, result.pe.imageBase, result.pe.sizeOfImage};
            return result;
        }
        if (options.representation == DumpRepresentation::MappedPEImage)
        {
            result.error = "Dump is not a complete RVA-mapped PE image";
            return result;
        }
    }

    if (options.representation != DumpRepresentation::RawSnapshot || options.imageBase == 0 ||
        options.architecture == DumpArchitecture::Unknown || options.moduleSize == 0)
    {
        result.error = "Unknown dump format; specify raw snapshot architecture, image base, and module size";
        return result;
    }
    if (options.moduleSize > bytes.size() || options.moduleSize > kMaximumDumpSize ||
        options.imageBase > (std::numeric_limits<uint64_t>::max)() - options.moduleSize)
    {
        result.error = "Raw dump metadata is inconsistent with the file size or address range";
        return result;
    }

    result.success = true;
    result.representation = DumpRepresentation::RawSnapshot;
    result.architecture = options.architecture;
    result.imageBytes.assign(bytes.begin(), bytes.begin() + static_cast<size_t>(options.moduleSize));
    result.pe.valid = true;
    result.pe.is64bit = options.architecture == DumpArchitecture::X64;
    result.pe.machine = result.pe.is64bit ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    result.pe.imageBase = options.imageBase;
    result.pe.sizeOfImage = static_cast<uint32_t>(options.moduleSize);
    PESectionInfo section{};
    std::memcpy(section.name, ".snapshot", 8);
    section.virtualSize = static_cast<uint32_t>(options.moduleSize);
    section.rawDataSize = static_cast<uint32_t>(options.moduleSize);
    section.characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    result.pe.sections.push_back(section);
    result.module = {FileName(path), path, options.imageBase, options.moduleSize};
    return result;
}

} // namespace openreverse
