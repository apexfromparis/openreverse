#include "pe_parser.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <cstdio>

namespace openreverse {

namespace {

constexpr size_t kMaxPEFileSize = 256ULL * 1024ULL * 1024ULL;
constexpr size_t kMaxMappedImageSize = 256ULL * 1024ULL * 1024ULL;
constexpr uint16_t kMaxSections = 96;
constexpr uint32_t kMaxImports = 4096;
constexpr uint32_t kMaxExports = 10000;
constexpr uint32_t kMaxRuntimeFunctions = 100000;
constexpr size_t kMaxNameLength = 4096;
constexpr size_t kMaxDebugDirectories = 256;

struct CodeViewRsdsHeader {
    uint32_t signature = 0;
    GUID guid{};
    uint32_t age = 0;
};

std::string FormatGuid(const GUID& guid)
{
    char buffer[37]{};
    std::snprintf(buffer, sizeof(buffer),
        "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        static_cast<unsigned long>(guid.Data1), guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return buffer;
}

bool CheckedRange(size_t offset, size_t size, size_t total)
{
    return offset <= total && size <= total - offset;
}

bool CheckedArrayRange(size_t offset, size_t count, size_t elementSize, size_t total)
{
    return elementSize == 0 || (count <= (std::numeric_limits<size_t>::max)() / elementSize &&
        CheckedRange(offset, count * elementSize, total));
}

template<typename T>
bool ReadObject(const uint8_t* data, size_t dataSize, size_t offset, T& value)
{
    if (!data || !CheckedRange(offset, sizeof(T), dataSize))
        return false;
    std::memcpy(&value, data + offset, sizeof(T));
    return true;
}

bool ReadBoundedString(const uint8_t* data, size_t dataSize, size_t offset, std::string& value)
{
    value.clear();
    if (!data || offset >= dataSize)
        return false;
    const size_t available = std::min(kMaxNameLength, dataSize - offset);
    const void* terminator = std::memchr(data + offset, '\0', available);
    if (!terminator)
        return false;
    const auto* end = static_cast<const uint8_t*>(terminator);
    value.assign(reinterpret_cast<const char*>(data + offset), static_cast<size_t>(end - (data + offset)));
    return true;
}

bool ReadCodeViewRecord(const uint8_t* data, size_t dataSize, size_t offset,
                        size_t recordSize, PEInfo& info)
{
    if (recordSize < sizeof(CodeViewRsdsHeader) + 1 ||
        !CheckedRange(offset, recordSize, dataSize))
        return false;
    CodeViewRsdsHeader header{};
    if (!ReadObject(data, dataSize, offset, header) || header.signature != 0x53445352)
        return false;
    std::string path;
    if (!ReadBoundedString(data, std::min(dataSize, offset + recordSize),
                           offset + sizeof(header), path))
        return false;
    info.pdbGuid = FormatGuid(header.guid);
    info.pdbAge = header.age;
    info.pdbPath = std::move(path);
    return true;
}

bool ReadProcessExact(HANDLE processHandle, uint64_t address, void* buffer, size_t size)
{
    if (!processHandle || (!buffer && size != 0))
        return false;
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead) &&
        bytesRead == size;
}

bool ReadImageExact(HANDLE processHandle, uint64_t baseAddress, uint64_t mappedImageSize,
                    uint64_t rva, void* buffer, size_t size)
{
    if (rva > mappedImageSize || size > mappedImageSize - rva ||
        rva > (std::numeric_limits<uint64_t>::max)() - baseAddress)
        return false;
    return ReadProcessExact(processHandle, baseAddress + rva, buffer, size);
}

bool ReadImageString(HANDLE processHandle, uint64_t baseAddress, uint64_t mappedImageSize,
                     uint64_t rva, std::string& value)
{
    value.clear();
    if (rva >= mappedImageSize)
        return false;
    const size_t length = static_cast<size_t>(std::min<uint64_t>(256, mappedImageSize - rva));
    std::vector<char> buffer(length);
    if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, rva, buffer.data(), buffer.size()))
        return false;
    const auto terminator = std::find(buffer.begin(), buffer.end(), '\0');
    if (terminator == buffer.end())
        return false;
    value.assign(buffer.begin(), terminator);
    return true;
}

void NormalizeRuntimeFunctions(std::vector<PERuntimeFunction>& candidates, PEInfo& info)
{
    std::sort(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) {
        return left.beginRva < right.beginRva ||
            (left.beginRva == right.beginRva && left.endRva < right.endRva);
    });
    for (const auto& candidate : candidates)
    {
        if (candidate.beginRva >= candidate.endRva || candidate.endRva > info.sizeOfImage ||
            candidate.unwindInfoRva == 0 || candidate.unwindInfoRva >= info.sizeOfImage)
        {
            ++info.rejectedRuntimeFunctionCount;
            continue;
        }
        if (!info.runtimeFunctions.empty() &&
            candidate.beginRva < info.runtimeFunctions.back().endRva)
        {
            ++info.rejectedRuntimeFunctionCount;
            continue;
        }
        info.runtimeFunctions.push_back(candidate);
    }
}

} // namespace

PEInfo PEParser::Parse(HANDLE processHandle, uint64_t baseAddress, uint64_t mappedImageSize)
{
    PEInfo info;
    if (!processHandle || baseAddress == 0 || mappedImageSize < sizeof(IMAGE_DOS_HEADER) ||
        mappedImageSize > kMaxMappedImageSize)
        return info;

    IMAGE_DOS_HEADER dosHeader{};
    if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, 0, &dosHeader, sizeof(dosHeader)))
        return info;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew < 0 ||
        static_cast<uint64_t>(dosHeader.e_lfanew) > mappedImageSize)
        return info;

    info.dosMagic = dosHeader.e_magic;
    info.peOffset = dosHeader.e_lfanew;

    const uint64_t ntRva = static_cast<uint64_t>(dosHeader.e_lfanew);
    DWORD ntSig = 0;
    if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, ntRva, &ntSig, sizeof(ntSig)))
        return info;

    if (ntSig != IMAGE_NT_SIGNATURE)
        return info;

    IMAGE_FILE_HEADER fileHeader{};
    if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, ntRva + sizeof(DWORD),
                        &fileHeader, sizeof(fileHeader)))
        return info;

    if (fileHeader.NumberOfSections == 0 || fileHeader.NumberOfSections > kMaxSections)
        return info;

    info.machine = fileHeader.Machine;
    info.numberOfSections = fileHeader.NumberOfSections;
    info.timestamp = fileHeader.TimeDateStamp;

    uint16_t optMagic = 0;
    const uint64_t optRva = ntRva + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, optRva, &optMagic, sizeof(optMagic)))
        return info;

    if (optMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && optMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return info;
    info.is64bit = optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if ((info.is64bit && info.machine != IMAGE_FILE_MACHINE_AMD64) ||
        (!info.is64bit && info.machine != IMAGE_FILE_MACHINE_I386))
        return info;

    uint32_t importDirRVA = 0;
    uint32_t exportDirRVA = 0;
    uint32_t exportDirSize = 0;
    uint32_t exceptionDirRVA = 0;
    uint32_t exceptionDirSize = 0;
    uint32_t debugDirRVA = 0;
    uint32_t debugDirSize = 0;

    if (info.is64bit)
    {
        if (fileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
            return info;
        IMAGE_OPTIONAL_HEADER64 optHeader{};
        if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, optRva,
                            &optHeader, sizeof(optHeader)))
            return info;

        info.sizeOfImage = optHeader.SizeOfImage;
        info.sizeOfHeaders = optHeader.SizeOfHeaders;
        info.entryPoint = optHeader.AddressOfEntryPoint;
        info.imageBase = optHeader.ImageBase;

        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            importDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            exportDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportDirSize = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION)
        {
            exceptionDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
            exceptionDirSize = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
        }
        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG)
        {
            debugDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            debugDirSize = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }
    }
    else
    {
        if (fileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32))
            return info;
        IMAGE_OPTIONAL_HEADER32 optHeader{};
        if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, optRva,
                            &optHeader, sizeof(optHeader)))
            return info;

        info.sizeOfImage = optHeader.SizeOfImage;
        info.sizeOfHeaders = optHeader.SizeOfHeaders;
        info.entryPoint = optHeader.AddressOfEntryPoint;
        info.imageBase = optHeader.ImageBase;

        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            importDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            exportDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportDirSize = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (optHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG)
        {
            debugDirRVA = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            debugDirSize = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }
    }

    if (info.sizeOfImage == 0 || info.sizeOfImage > mappedImageSize ||
        info.imageBase > (std::numeric_limits<uint64_t>::max)() - info.sizeOfImage ||
        info.sizeOfHeaders == 0 || info.sizeOfHeaders > info.sizeOfImage ||
        (info.entryPoint != 0 && info.entryPoint >= info.sizeOfImage))
        return info;

    const uint64_t sectionTableRva = optRva + fileHeader.SizeOfOptionalHeader;
    if (!ParseSections(processHandle, baseAddress, mappedImageSize, sectionTableRva,
                       info.numberOfSections, info))
        return info;

    info.exceptionDirectoryRva = exceptionDirRVA;
    info.exceptionDirectorySize = exceptionDirSize;
    info.importDirectoryRva = importDirRVA;
    info.exportDirectoryRva = exportDirRVA;
    info.exportDirectorySize = exportDirSize;
    info.debugDirectoryRva = debugDirRVA;
    info.debugDirectorySize = debugDirSize;
    if (info.is64bit && exceptionDirRVA != 0 && exceptionDirSize != 0)
    {
        const size_t entrySize = sizeof(RUNTIME_FUNCTION);
        info.runtimeFunctionDirectoryComplete = exceptionDirSize % entrySize == 0;
        const size_t declaredCount = exceptionDirSize / entrySize;
        const size_t count = std::min<size_t>(declaredCount, kMaxRuntimeFunctions);
        if (declaredCount > kMaxRuntimeFunctions)
            info.runtimeFunctionDirectoryComplete = false;
        std::vector<PERuntimeFunction> candidates;
        candidates.reserve(count);
        for (size_t i = 0; i < count; ++i)
        {
            RUNTIME_FUNCTION entry{};
            const uint64_t rva = static_cast<uint64_t>(exceptionDirRVA) + i * entrySize;
            if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, rva, &entry, sizeof(entry)))
            {
                info.runtimeFunctionDirectoryComplete = false;
                break;
            }
            candidates.push_back({entry.BeginAddress, entry.EndAddress, entry.UnwindInfoAddress});
        }
        NormalizeRuntimeFunctions(candidates, info);
    }

    if (importDirRVA != 0)
        ParseImports(processHandle, baseAddress, mappedImageSize, importDirRVA, info.is64bit, info);

    if (exportDirRVA != 0)
        ParseExports(processHandle, baseAddress, mappedImageSize, exportDirRVA,
                     exportDirSize, info.is64bit, info);

    ParseCodeViewLive(processHandle, baseAddress, mappedImageSize, info);

    info.valid = true;
    return info;
}

bool PEParser::ParseSections(HANDLE processHandle, uint64_t baseAddress, uint64_t mappedImageSize,
                             uint64_t sectionTableRVA, uint16_t numSections, PEInfo& info)
{
    for (uint16_t i = 0; i < numSections && i < kMaxSections; ++i)
    {
        IMAGE_SECTION_HEADER sec{};
        const uint64_t sectionRva = sectionTableRVA + static_cast<uint64_t>(i) * sizeof(IMAGE_SECTION_HEADER);
        if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, sectionRva, &sec, sizeof(sec)))
            return false;

        PESectionInfo si{};
        memset(si.name, 0, sizeof(si.name));
        memcpy(si.name, sec.Name, 8);
        si.virtualAddress = sec.VirtualAddress;
        si.virtualSize = sec.Misc.VirtualSize;
        si.rawDataOffset = sec.PointerToRawData;
        si.rawDataSize = sec.SizeOfRawData;
        si.characteristics = sec.Characteristics;

        const uint64_t span = std::max<uint64_t>(si.virtualSize, si.rawDataSize);
        if (span != 0 && (si.virtualAddress >= info.sizeOfImage || span > info.sizeOfImage - si.virtualAddress))
            return false;

        info.sections.push_back(si);
    }
    return info.sections.size() == numSections;
}

void PEParser::ParseImports(HANDLE processHandle, uint64_t baseAddress, uint64_t mappedImageSize,
                            uint32_t importDirRVA, bool is64bit, PEInfo& info)
{
    for (uint32_t i = 0; i < 256; ++i)
    {
        IMAGE_IMPORT_DESCRIPTOR desc{};
        const uint64_t descriptorRva = static_cast<uint64_t>(importDirRVA) +
            static_cast<uint64_t>(i) * sizeof(desc);
        if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, descriptorRva,
                            &desc, sizeof(desc)))
            break;

        if (desc.Name == 0 && desc.OriginalFirstThunk == 0 && desc.FirstThunk == 0)
            break;

        PEImportEntry entry;
        if (!ReadImageString(processHandle, baseAddress, mappedImageSize, desc.Name, entry.dllName) ||
            entry.dllName.empty())
            continue;

        const uint32_t thunkRva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        for (int j = 0; j < 100; ++j)
        {
            uint64_t thunkValue = 0;
            const size_t thunkSize = is64bit ? sizeof(uint64_t) : sizeof(uint32_t);
            const uint64_t currentThunkRva = static_cast<uint64_t>(thunkRva) +
                static_cast<uint64_t>(j) * thunkSize;

            if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, currentThunkRva,
                                &thunkValue, thunkSize))
                break;

            if (thunkValue == 0)
                break;

            bool byOrdinal = is64bit
                ? (thunkValue & 0x8000000000000000ULL) != 0
                : (thunkValue & 0x80000000ULL) != 0;

            if (byOrdinal)
            {
                uint16_t ord = (uint16_t)(thunkValue & 0xFFFF);
                entry.functions.push_back("Ordinal#" + std::to_string(ord));
            }
            else
            {
                const uint64_t hintNameRva = is64bit
                    ? (thunkValue & ~IMAGE_ORDINAL_FLAG64)
                    : (thunkValue & ~static_cast<uint64_t>(IMAGE_ORDINAL_FLAG32));
                if (hintNameRva > (std::numeric_limits<uint32_t>::max)())
                    break;
                std::string functionName;
                if (ReadImageString(processHandle, baseAddress, mappedImageSize,
                                    hintNameRva + sizeof(uint16_t), functionName) && !functionName.empty())
                    entry.functions.push_back(functionName);
            }
        }

        info.imports.push_back(entry);
    }
}

void PEParser::ParseExports(HANDLE processHandle, uint64_t baseAddress, uint64_t mappedImageSize,
                            uint32_t exportDirRVA, uint32_t exportDirSize, bool is64bit, PEInfo& info)
{
    (void)is64bit;
    IMAGE_EXPORT_DIRECTORY exportDir{};
    if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, exportDirRVA,
                        &exportDir, sizeof(exportDir)))
        return;

    uint32_t numFuncs = exportDir.NumberOfFunctions;
    uint32_t numNames = exportDir.NumberOfNames;
    if (numFuncs == 0 || numFuncs > kMaxExports || numNames > kMaxExports)
        return;

    std::vector<uint32_t> funcRVAs(numFuncs);
    if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, exportDir.AddressOfFunctions,
                        funcRVAs.data(), numFuncs * sizeof(uint32_t)))
        return;

    std::vector<uint32_t> nameRVAs(numNames);
    std::vector<uint16_t> ordinals(numNames);
    if (numNames > 0)
    {
        if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, exportDir.AddressOfNames,
                            nameRVAs.data(), numNames * sizeof(uint32_t)) ||
            !ReadImageExact(processHandle, baseAddress, mappedImageSize, exportDir.AddressOfNameOrdinals,
                            ordinals.data(), numNames * sizeof(uint16_t)))
            return;
    }

    for (uint32_t i = 0; i < numFuncs && i < 2000; ++i)
    {
        if (funcRVAs[i] == 0) continue;

        PEInfo::PEExportEntry ee;
        ee.rva = funcRVAs[i];
        ee.ordinal = exportDir.Base + i;
        ee.name = "Ordinal#" + std::to_string(ee.ordinal);
        if (exportDirSize != 0 && ee.rva >= exportDirRVA &&
            static_cast<uint64_t>(ee.rva) - exportDirRVA < exportDirSize)
        {
            std::string forwarder;
            if (ReadImageString(processHandle, baseAddress, mappedImageSize, ee.rva, forwarder))
            {
                ee.isForwarder = true;
                ee.forwarder = forwarder;
            }
        }

        for (uint32_t j = 0; j < numNames; ++j)
        {
            if (ordinals[j] == i)
            {
                std::string exportName;
                if (ReadImageString(processHandle, baseAddress, mappedImageSize, nameRVAs[j], exportName) &&
                    !exportName.empty())
                    ee.name = exportName;
                break;
            }
        }
        info.exports.push_back(ee);
    }
}

PEInfo PEParser::ParseFile(const std::string& filePath, std::vector<uint8_t>& rawBufferOut)
{
    rawBufferOut.clear();

    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return {};

    LARGE_INTEGER fileSizeValue{};
    if (!GetFileSizeEx(hFile, &fileSizeValue) || fileSizeValue.QuadPart < static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER)) ||
        fileSizeValue.QuadPart > static_cast<LONGLONG>(kMaxPEFileSize))
    {
        CloseHandle(hFile);
        return {};
    }

    const size_t fileSize = static_cast<size_t>(fileSizeValue.QuadPart);
    rawBufferOut.resize(fileSize);
    size_t totalRead = 0;
    while (totalRead < fileSize)
    {
        DWORD bytesRead = 0;
        DWORD toRead = static_cast<DWORD>(std::min<size_t>(fileSize - totalRead, 16ULL * 1024ULL * 1024ULL));
        if (!ReadFile(hFile, rawBufferOut.data() + totalRead, toRead, &bytesRead, nullptr) || bytesRead == 0)
            break;
        totalRead += bytesRead;
    }
    CloseHandle(hFile);

    if (totalRead != fileSize)
    {
        rawBufferOut.clear();
        return {};
    }

    return ParseBuffer(rawBufferOut.data(), rawBufferOut.size());
}

PEInfo PEParser::ParseBuffer(const uint8_t* data, size_t fileSize)
{
    PEInfo info;
    IMAGE_DOS_HEADER dosHeader{};
    if (!ReadObject(data, fileSize, 0, dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew < 0)
        return info;

    const size_t ntOffset = static_cast<size_t>(dosHeader.e_lfanew);
    DWORD ntSignature = 0;
    IMAGE_FILE_HEADER fileHeader{};
    if (!ReadObject(data, fileSize, ntOffset, ntSignature) || ntSignature != IMAGE_NT_SIGNATURE ||
        !ReadObject(data, fileSize, ntOffset + sizeof(DWORD), fileHeader) ||
        fileHeader.NumberOfSections == 0 || fileHeader.NumberOfSections > kMaxSections)
    {
        return info;
    }

    const size_t optionalOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!CheckedRange(optionalOffset, fileHeader.SizeOfOptionalHeader, fileSize))
        return info;

    uint16_t optionalMagic = 0;
    if (!ReadObject(data, fileSize, optionalOffset, optionalMagic) ||
        (optionalMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && optionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    {
        return info;
    }

    info.dosMagic = dosHeader.e_magic;
    info.peOffset = static_cast<uint32_t>(ntOffset);
    info.machine = fileHeader.Machine;
    info.numberOfSections = fileHeader.NumberOfSections;
    info.timestamp = fileHeader.TimeDateStamp;
    info.is64bit = optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    uint32_t importDirRVA = 0;
    uint32_t exportDirRVA = 0;
    uint32_t exportDirSize = 0;
    uint32_t exceptionDirRVA = 0;
    uint32_t exceptionDirSize = 0;
    uint32_t debugDirRVA = 0;
    uint32_t debugDirSize = 0;
    if (info.is64bit)
    {
        if (fileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
            return {};
        IMAGE_OPTIONAL_HEADER64 optionalHeader{};
        if (!ReadObject(data, fileSize, optionalOffset, optionalHeader))
            return {};
        info.sizeOfImage = optionalHeader.SizeOfImage;
        info.sizeOfHeaders = optionalHeader.SizeOfHeaders;
        info.entryPoint = optionalHeader.AddressOfEntryPoint;
        info.imageBase = optionalHeader.ImageBase;
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            importDirRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            exportDirRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportDirSize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION)
        {
            exceptionDirRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
            exceptionDirSize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG)
        {
            debugDirRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            debugDirSize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }
    }
    else
    {
        if (fileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32))
            return {};
        IMAGE_OPTIONAL_HEADER32 optionalHeader{};
        if (!ReadObject(data, fileSize, optionalOffset, optionalHeader))
            return {};
        info.sizeOfImage = optionalHeader.SizeOfImage;
        info.sizeOfHeaders = optionalHeader.SizeOfHeaders;
        info.entryPoint = optionalHeader.AddressOfEntryPoint;
        info.imageBase = optionalHeader.ImageBase;
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            importDirRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            exportDirRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportDirSize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
        if (optionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG)
        {
            debugDirRVA = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            debugDirSize = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
        }
    }

    if (info.sizeOfImage == 0 || info.sizeOfImage > kMaxMappedImageSize ||
        info.imageBase > (std::numeric_limits<uint64_t>::max)() - info.sizeOfImage ||
        info.sizeOfHeaders == 0 || info.sizeOfHeaders > info.sizeOfImage || info.sizeOfHeaders > fileSize ||
        (info.entryPoint != 0 && info.entryPoint >= info.sizeOfImage))
    {
        return {};
    }
    if ((info.is64bit && info.machine != IMAGE_FILE_MACHINE_AMD64) ||
        (!info.is64bit && info.machine != IMAGE_FILE_MACHINE_I386))
    {
        return {};
    }

    const size_t sectionOffset = optionalOffset + fileHeader.SizeOfOptionalHeader;
    if (!CheckedArrayRange(sectionOffset, info.numberOfSections, sizeof(IMAGE_SECTION_HEADER), fileSize))
        return {};

    for (uint16_t i = 0; i < info.numberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER sectionHeader{};
        if (!ReadObject(data, fileSize, sectionOffset + i * sizeof(IMAGE_SECTION_HEADER), sectionHeader))
            return {};

        PESectionInfo si{};
        memcpy(si.name, sectionHeader.Name, 8);
        si.name[8] = 0;
        si.virtualAddress = sectionHeader.VirtualAddress;
        si.virtualSize = sectionHeader.Misc.VirtualSize;
        si.rawDataOffset = sectionHeader.PointerToRawData;
        si.rawDataSize = sectionHeader.SizeOfRawData;
        si.characteristics = sectionHeader.Characteristics;

        const uint64_t virtualSpan = std::max<uint64_t>(si.virtualSize, si.rawDataSize);
        if (virtualSpan != 0 && (si.virtualAddress >= info.sizeOfImage || virtualSpan > info.sizeOfImage - si.virtualAddress))
            return {};
        if (si.rawDataSize != 0 && !CheckedRange(si.rawDataOffset, si.rawDataSize, fileSize))
            return {};
        info.sections.push_back(si);
    }

    info.valid = true;
    info.exceptionDirectoryRva = exceptionDirRVA;
    info.exceptionDirectorySize = exceptionDirSize;
    info.importDirectoryRva = importDirRVA;
    info.exportDirectoryRva = exportDirRVA;
    info.exportDirectorySize = exportDirSize;
    info.debugDirectoryRva = debugDirRVA;
    info.debugDirectorySize = debugDirSize;
    ParseRuntimeFunctionsRaw(data, fileSize, info);
    if (importDirRVA != 0)
        ParseImportsOffline(data, fileSize, importDirRVA, info.is64bit, info);
    if (exportDirRVA != 0)
        ParseExportsOffline(data, fileSize, exportDirRVA, exportDirSize, info.is64bit, info);
    ParseCodeViewRaw(data, fileSize, info);

    return info;
}

bool PEParser::RvaToFileOffset(uint32_t rva, size_t requiredSize, const PEInfo& info,
                               size_t fileSize, size_t& offsetOut)
{
    offsetOut = 0;
    if (!info.valid)
        return false;

    if (rva < info.sizeOfHeaders)
    {
        if (requiredSize > info.sizeOfHeaders - rva || !CheckedRange(rva, requiredSize, fileSize))
            return false;
        offsetOut = rva;
        return true;
    }

    for (const auto& section : info.sections)
    {
        const uint64_t sectionSpan = std::max<uint64_t>(section.virtualSize, section.rawDataSize);
        if (rva < section.virtualAddress || static_cast<uint64_t>(rva) - section.virtualAddress >= sectionSpan)
            continue;

        const uint64_t delta = static_cast<uint64_t>(rva) - section.virtualAddress;
        if (delta > section.rawDataSize || requiredSize > section.rawDataSize - static_cast<size_t>(delta))
            return false;
        const uint64_t rawOffset = static_cast<uint64_t>(section.rawDataOffset) + delta;
        if (rawOffset > (std::numeric_limits<size_t>::max)() ||
            !CheckedRange(static_cast<size_t>(rawOffset), requiredSize, fileSize))
            return false;
        offsetOut = static_cast<size_t>(rawOffset);
        return true;
    }
    return false;
}

bool PEParser::BuildMappedImage(const std::vector<uint8_t>& rawBuffer, const PEInfo& info,
                                std::vector<uint8_t>& mappedImageOut)
{
    mappedImageOut.clear();
    if (!info.valid || rawBuffer.empty() || info.sizeOfImage == 0 || info.sizeOfImage > kMaxMappedImageSize ||
        info.sizeOfHeaders > rawBuffer.size() || info.sizeOfHeaders > info.sizeOfImage)
    {
        return false;
    }

    mappedImageOut.assign(info.sizeOfImage, 0);
    std::memcpy(mappedImageOut.data(), rawBuffer.data(), info.sizeOfHeaders);

    for (const auto& section : info.sections)
    {
        if (section.rawDataSize == 0)
            continue;
        if (!CheckedRange(section.rawDataOffset, section.rawDataSize, rawBuffer.size()) ||
            section.virtualAddress > mappedImageOut.size() ||
            section.rawDataSize > mappedImageOut.size() - section.virtualAddress)
        {
            mappedImageOut.clear();
            return false;
        }
        std::memcpy(mappedImageOut.data() + section.virtualAddress,
                    rawBuffer.data() + section.rawDataOffset, section.rawDataSize);
    }
    return true;
}

PEInfo PEParser::ParseMappedImage(const uint8_t* data, size_t mappedImageSize,
                                  uint64_t imageBaseOverride)
{
    PEInfo info = ParseBuffer(data, mappedImageSize);
    if (!info.valid || mappedImageSize < info.sizeOfImage)
        return {};

    info.imports.clear();
    info.exports.clear();
    info.runtimeFunctions.clear();
    info.rejectedRuntimeFunctionCount = 0;
    info.pdbGuid.clear();
    info.pdbAge = 0;
    info.pdbPath.clear();
    if (imageBaseOverride != 0)
    {
        if (imageBaseOverride > (std::numeric_limits<uint64_t>::max)() - info.sizeOfImage)
            return {};
        info.imageBase = imageBaseOverride;
    }
    ParseRuntimeFunctionsMapped(data, mappedImageSize, info);
    ParseImportsMapped(data, mappedImageSize, info);
    ParseExportsMapped(data, mappedImageSize, info);
    ParseCodeViewMapped(data, mappedImageSize, info);
    return info;
}

void PEParser::ParseRuntimeFunctionsRaw(const uint8_t* data, size_t fileSize, PEInfo& info)
{
    if (!info.valid || !info.is64bit || info.exceptionDirectoryRva == 0 ||
        info.exceptionDirectorySize == 0)
        return;

    const size_t entrySize = sizeof(RUNTIME_FUNCTION);
    info.runtimeFunctionDirectoryComplete = info.exceptionDirectorySize % entrySize == 0;
    const size_t declaredCount = info.exceptionDirectorySize / entrySize;
    const size_t count = std::min<size_t>(declaredCount, kMaxRuntimeFunctions);
    if (declaredCount > kMaxRuntimeFunctions)
        info.runtimeFunctionDirectoryComplete = false;

    std::vector<PERuntimeFunction> candidates;
    candidates.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
        const uint64_t entryRva = static_cast<uint64_t>(info.exceptionDirectoryRva) + i * entrySize;
        if (entryRva > (std::numeric_limits<uint32_t>::max)())
        {
            info.runtimeFunctionDirectoryComplete = false;
            break;
        }
        size_t fileOffset = 0;
        RUNTIME_FUNCTION entry{};
        if (!RvaToFileOffset(static_cast<uint32_t>(entryRva), sizeof(entry), info, fileSize, fileOffset) ||
            !ReadObject(data, fileSize, fileOffset, entry))
        {
            info.runtimeFunctionDirectoryComplete = false;
            break;
        }
        candidates.push_back({entry.BeginAddress, entry.EndAddress, entry.UnwindInfoAddress});
    }
    NormalizeRuntimeFunctions(candidates, info);
}

void PEParser::ParseRuntimeFunctionsMapped(const uint8_t* data, size_t mappedImageSize, PEInfo& info)
{
    if (!info.valid || !info.is64bit || info.exceptionDirectoryRva == 0 ||
        info.exceptionDirectorySize == 0)
        return;

    const size_t entrySize = sizeof(RUNTIME_FUNCTION);
    info.runtimeFunctionDirectoryComplete = info.exceptionDirectorySize % entrySize == 0;
    const size_t declaredCount = info.exceptionDirectorySize / entrySize;
    const size_t count = std::min<size_t>(declaredCount, kMaxRuntimeFunctions);
    if (declaredCount > kMaxRuntimeFunctions)
        info.runtimeFunctionDirectoryComplete = false;

    std::vector<PERuntimeFunction> candidates;
    candidates.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
        const uint64_t offset = static_cast<uint64_t>(info.exceptionDirectoryRva) + i * entrySize;
        RUNTIME_FUNCTION entry{};
        if (!CheckedRange(static_cast<size_t>(offset), sizeof(entry), mappedImageSize) ||
            !ReadObject(data, mappedImageSize, static_cast<size_t>(offset), entry))
        {
            info.runtimeFunctionDirectoryComplete = false;
            break;
        }
        candidates.push_back({entry.BeginAddress, entry.EndAddress, entry.UnwindInfoAddress});
    }
    NormalizeRuntimeFunctions(candidates, info);
}

void PEParser::ParseImportsMapped(const uint8_t* data, size_t mappedImageSize, PEInfo& info)
{
    if (info.importDirectoryRva == 0) return;
    for (uint32_t index = 0; index < kMaxImports; ++index)
    {
        const uint64_t descriptorOffset = static_cast<uint64_t>(info.importDirectoryRva) +
            static_cast<uint64_t>(index) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        if (descriptorOffset > (std::numeric_limits<size_t>::max)() ||
            !ReadObject(data, mappedImageSize, static_cast<size_t>(descriptorOffset), descriptor))
            break;
        if (descriptor.Name == 0 && descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0)
            break;
        PEImportEntry imported;
        if (!ReadBoundedString(data, mappedImageSize, descriptor.Name, imported.dllName) ||
            imported.dllName.empty())
            continue;
        const uint32_t thunkRva = descriptor.OriginalFirstThunk
            ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
        const size_t thunkSize = info.is64bit ? sizeof(uint64_t) : sizeof(uint32_t);
        for (uint32_t thunkIndex = 0; thunkIndex < kMaxImports && thunkRva != 0; ++thunkIndex)
        {
            const uint64_t thunkOffset = static_cast<uint64_t>(thunkRva) +
                static_cast<uint64_t>(thunkIndex) * thunkSize;
            if (thunkOffset > (std::numeric_limits<size_t>::max)()) break;
            uint64_t thunkValue = 0;
            if (info.is64bit)
            {
                if (!ReadObject(data, mappedImageSize, static_cast<size_t>(thunkOffset), thunkValue)) break;
            }
            else
            {
                uint32_t value = 0;
                if (!ReadObject(data, mappedImageSize, static_cast<size_t>(thunkOffset), value)) break;
                thunkValue = value;
            }
            if (thunkValue == 0) break;
            const bool ordinal = info.is64bit
                ? (thunkValue & IMAGE_ORDINAL_FLAG64) != 0
                : (thunkValue & IMAGE_ORDINAL_FLAG32) != 0;
            if (ordinal)
            {
                imported.functions.push_back(
                    "Ordinal#" + std::to_string(static_cast<uint16_t>(thunkValue & 0xFFFF)));
                continue;
            }
            const uint64_t hintRva = info.is64bit
                ? (thunkValue & ~IMAGE_ORDINAL_FLAG64)
                : (thunkValue & ~static_cast<uint64_t>(IMAGE_ORDINAL_FLAG32));
            if (hintRva > (std::numeric_limits<size_t>::max)() ||
                hintRva >= mappedImageSize || sizeof(uint16_t) > mappedImageSize - hintRva)
                continue;
            std::string name;
            if (ReadBoundedString(data, mappedImageSize,
                                  static_cast<size_t>(hintRva) + sizeof(uint16_t), name) &&
                !name.empty())
                imported.functions.push_back(std::move(name));
        }
        info.imports.push_back(std::move(imported));
    }
}

void PEParser::ParseExportsMapped(const uint8_t* data, size_t mappedImageSize, PEInfo& info)
{
    if (info.exportDirectoryRva == 0) return;
    IMAGE_EXPORT_DIRECTORY directory{};
    if (!ReadObject(data, mappedImageSize, info.exportDirectoryRva, directory) ||
        directory.NumberOfFunctions == 0 || directory.NumberOfFunctions > kMaxExports ||
        directory.NumberOfNames > kMaxExports)
        return;
    if (!CheckedArrayRange(directory.AddressOfFunctions, directory.NumberOfFunctions,
                           sizeof(uint32_t), mappedImageSize) ||
        !CheckedArrayRange(directory.AddressOfNames, directory.NumberOfNames,
                           sizeof(uint32_t), mappedImageSize) ||
        !CheckedArrayRange(directory.AddressOfNameOrdinals, directory.NumberOfNames,
                           sizeof(uint16_t), mappedImageSize))
        return;

    std::vector<uint32_t> functions(directory.NumberOfFunctions);
    std::vector<uint32_t> names(directory.NumberOfNames);
    std::vector<uint16_t> ordinals(directory.NumberOfNames);
    std::memcpy(functions.data(), data + directory.AddressOfFunctions,
                functions.size() * sizeof(uint32_t));
    if (!names.empty())
    {
        std::memcpy(names.data(), data + directory.AddressOfNames, names.size() * sizeof(uint32_t));
        std::memcpy(ordinals.data(), data + directory.AddressOfNameOrdinals,
                    ordinals.size() * sizeof(uint16_t));
    }
    for (uint32_t index = 0; index < directory.NumberOfFunctions; ++index)
    {
        if (functions[index] == 0) continue;
        PEInfo::PEExportEntry exported;
        exported.rva = functions[index];
        exported.ordinal = directory.Base + index;
        exported.name = "Ordinal#" + std::to_string(exported.ordinal);
        if (info.exportDirectorySize != 0 && exported.rva >= info.exportDirectoryRva &&
            exported.rva - info.exportDirectoryRva < info.exportDirectorySize)
        {
            if (ReadBoundedString(data, mappedImageSize, exported.rva, exported.forwarder))
                exported.isForwarder = true;
        }
        for (size_t nameIndex = 0; nameIndex < names.size(); ++nameIndex)
        {
            if (ordinals[nameIndex] != index) continue;
            std::string name;
            if (ReadBoundedString(data, mappedImageSize, names[nameIndex], name) && !name.empty())
                exported.name = std::move(name);
            break;
        }
        info.exports.push_back(std::move(exported));
    }
}

void PEParser::ParseImportsOffline(const uint8_t* data, size_t fileSize,
                                   uint32_t importDirRVA, bool is64bit, PEInfo& info)
{
    for (uint32_t i = 0; i < kMaxImports; ++i)
    {
        const uint64_t descriptorRva = static_cast<uint64_t>(importDirRVA) + i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (descriptorRva > (std::numeric_limits<uint32_t>::max)())
            break;

        size_t descriptorOffset = 0;
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        if (!RvaToFileOffset(static_cast<uint32_t>(descriptorRva), sizeof(descriptor), info, fileSize, descriptorOffset) ||
            !ReadObject(data, fileSize, descriptorOffset, descriptor))
            break;
        if (descriptor.Name == 0 && descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0)
            break;

        size_t nameOffset = 0;
        std::string dllName;
        if (!RvaToFileOffset(descriptor.Name, 1, info, fileSize, nameOffset) ||
            !ReadBoundedString(data, fileSize, nameOffset, dllName) || dllName.empty())
            continue;

        PEImportEntry entry;
        entry.dllName = dllName;

        const uint32_t thunkRva = descriptor.OriginalFirstThunk ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
        const size_t thunkSize = is64bit ? sizeof(uint64_t) : sizeof(uint32_t);
        for (uint32_t j = 0; j < kMaxImports && thunkRva != 0; ++j)
        {
            const uint64_t currentThunkRva = static_cast<uint64_t>(thunkRva) + static_cast<uint64_t>(j) * thunkSize;
            if (currentThunkRva > (std::numeric_limits<uint32_t>::max)())
                break;
            size_t thunkOffset = 0;
            if (!RvaToFileOffset(static_cast<uint32_t>(currentThunkRva), thunkSize, info, fileSize, thunkOffset))
                break;

            uint64_t thunkValue = 0;
            if (is64bit)
            {
                if (!ReadObject(data, fileSize, thunkOffset, thunkValue)) break;
            }
            else
            {
                uint32_t thunk32 = 0;
                if (!ReadObject(data, fileSize, thunkOffset, thunk32)) break;
                thunkValue = thunk32;
            }
            if (thunkValue == 0)
                break;

            const bool byOrdinal = is64bit
                ? (thunkValue & IMAGE_ORDINAL_FLAG64) != 0
                : (thunkValue & IMAGE_ORDINAL_FLAG32) != 0;
            if (byOrdinal)
            {
                entry.functions.push_back("Ordinal#" + std::to_string(static_cast<uint16_t>(thunkValue & 0xFFFF)));
                continue;
            }

            const uint64_t hintRva64 = is64bit
                ? (thunkValue & ~IMAGE_ORDINAL_FLAG64)
                : (thunkValue & ~static_cast<uint64_t>(IMAGE_ORDINAL_FLAG32));
            if (hintRva64 > (std::numeric_limits<uint32_t>::max)())
                continue;
            size_t hintOffset = 0;
            std::string functionName;
            if (RvaToFileOffset(static_cast<uint32_t>(hintRva64), sizeof(uint16_t) + 1, info, fileSize, hintOffset) &&
                ReadBoundedString(data, fileSize, hintOffset + sizeof(uint16_t), functionName) && !functionName.empty())
            {
                entry.functions.push_back(functionName);
            }
        }
        info.imports.push_back(entry);
    }
}

void PEParser::ParseExportsOffline(const uint8_t* data, size_t fileSize,
                                   uint32_t exportDirRVA, uint32_t exportDirSize, bool is64bit, PEInfo& info)
{
    (void)is64bit;
    size_t directoryOffset = 0;
    IMAGE_EXPORT_DIRECTORY exportDirectory{};
    if (!RvaToFileOffset(exportDirRVA, sizeof(exportDirectory), info, fileSize, directoryOffset) ||
        !ReadObject(data, fileSize, directoryOffset, exportDirectory) ||
        exportDirectory.NumberOfFunctions == 0 || exportDirectory.NumberOfFunctions > kMaxExports ||
        exportDirectory.NumberOfNames > kMaxExports)
        return;

    size_t functionsOffset = 0;
    size_t namesOffset = 0;
    size_t ordinalsOffset = 0;
    if (!RvaToFileOffset(exportDirectory.AddressOfFunctions,
                         exportDirectory.NumberOfFunctions * sizeof(uint32_t), info, fileSize, functionsOffset))
        return;
    if (exportDirectory.NumberOfNames != 0 &&
        (!RvaToFileOffset(exportDirectory.AddressOfNames,
                          exportDirectory.NumberOfNames * sizeof(uint32_t), info, fileSize, namesOffset) ||
         !RvaToFileOffset(exportDirectory.AddressOfNameOrdinals,
                          exportDirectory.NumberOfNames * sizeof(uint16_t), info, fileSize, ordinalsOffset)))
        return;

    std::map<uint16_t, std::string> namesByIndex;
    for (uint32_t i = 0; i < exportDirectory.NumberOfNames; ++i)
    {
        uint32_t nameRva = 0;
        uint16_t ordinalIndex = 0;
        if (!ReadObject(data, fileSize, namesOffset + i * sizeof(uint32_t), nameRva) ||
            !ReadObject(data, fileSize, ordinalsOffset + i * sizeof(uint16_t), ordinalIndex) ||
            ordinalIndex >= exportDirectory.NumberOfFunctions)
            continue;

        size_t nameOffset = 0;
        std::string exportName;
        if (!RvaToFileOffset(nameRva, 1, info, fileSize, nameOffset) ||
            !ReadBoundedString(data, fileSize, nameOffset, exportName) || exportName.empty())
            continue;
        namesByIndex[ordinalIndex] = exportName;
    }

    for (uint32_t functionIndex = 0; functionIndex < exportDirectory.NumberOfFunctions; ++functionIndex)
    {
        uint32_t functionRva = 0;
        if (!ReadObject(data, fileSize, functionsOffset + functionIndex * sizeof(uint32_t), functionRva) ||
            functionRva == 0)
            continue;

        const uint64_t ordinal = static_cast<uint64_t>(exportDirectory.Base) + functionIndex;
        if (ordinal > (std::numeric_limits<uint32_t>::max)())
            continue;

        PEInfo::PEExportEntry ee;
        const auto name = namesByIndex.find(static_cast<uint16_t>(functionIndex));
        ee.name = name == namesByIndex.end()
            ? "Ordinal#" + std::to_string(ordinal)
            : name->second;
        ee.rva = functionRva;
        ee.ordinal = static_cast<uint32_t>(ordinal);
        ee.isForwarder = exportDirSize != 0 && functionRva >= exportDirRVA &&
            static_cast<uint64_t>(functionRva) - exportDirRVA < exportDirSize;
        if (ee.isForwarder)
        {
            size_t forwarderOffset = 0;
            if (!RvaToFileOffset(functionRva, 1, info, fileSize, forwarderOffset) ||
                !ReadBoundedString(data, fileSize, forwarderOffset, ee.forwarder) || ee.forwarder.empty())
                continue;
        }
        info.exports.push_back(ee);
    }
}

void PEParser::ParseCodeViewRaw(const uint8_t* data, size_t fileSize, PEInfo& info)
{
    if (!info.valid || info.debugDirectoryRva == 0 ||
        info.debugDirectorySize < sizeof(IMAGE_DEBUG_DIRECTORY))
        return;
    const size_t declaredCount = info.debugDirectorySize / sizeof(IMAGE_DEBUG_DIRECTORY);
    const size_t count = std::min(declaredCount, kMaxDebugDirectories);
    for (size_t index = 0; index < count; ++index)
    {
        const uint64_t entryRva = static_cast<uint64_t>(info.debugDirectoryRva) +
            index * sizeof(IMAGE_DEBUG_DIRECTORY);
        if (entryRva > (std::numeric_limits<uint32_t>::max)()) break;
        size_t entryOffset = 0;
        IMAGE_DEBUG_DIRECTORY entry{};
        if (!RvaToFileOffset(static_cast<uint32_t>(entryRva), sizeof(entry), info,
                             fileSize, entryOffset) ||
            !ReadObject(data, fileSize, entryOffset, entry))
            break;
        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData == 0 ||
            entry.SizeOfData > sizeof(CodeViewRsdsHeader) + kMaxNameLength)
            continue;
        size_t recordOffset = entry.PointerToRawData;
        if (!CheckedRange(recordOffset, entry.SizeOfData, fileSize))
        {
            if (!RvaToFileOffset(entry.AddressOfRawData, entry.SizeOfData, info,
                                 fileSize, recordOffset))
                continue;
        }
        if (ReadCodeViewRecord(data, fileSize, recordOffset, entry.SizeOfData, info))
            return;
    }
}

void PEParser::ParseCodeViewMapped(const uint8_t* data, size_t mappedImageSize, PEInfo& info)
{
    if (!info.valid || info.debugDirectoryRva == 0 ||
        info.debugDirectorySize < sizeof(IMAGE_DEBUG_DIRECTORY) ||
        info.debugDirectoryRva >= mappedImageSize)
        return;
    const size_t declaredCount = info.debugDirectorySize / sizeof(IMAGE_DEBUG_DIRECTORY);
    const size_t count = std::min(declaredCount, kMaxDebugDirectories);
    for (size_t index = 0; index < count; ++index)
    {
        const uint64_t entryOffset = static_cast<uint64_t>(info.debugDirectoryRva) +
            index * sizeof(IMAGE_DEBUG_DIRECTORY);
        if (entryOffset > (std::numeric_limits<size_t>::max)()) break;
        IMAGE_DEBUG_DIRECTORY entry{};
        if (!ReadObject(data, mappedImageSize, static_cast<size_t>(entryOffset), entry))
            break;
        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData == 0 ||
            entry.SizeOfData > sizeof(CodeViewRsdsHeader) + kMaxNameLength)
            continue;
        if (ReadCodeViewRecord(data, mappedImageSize, entry.AddressOfRawData,
                               entry.SizeOfData, info))
            return;
    }
}

void PEParser::ParseCodeViewLive(HANDLE processHandle, uint64_t baseAddress,
                                 uint64_t mappedImageSize, PEInfo& info)
{
    if (info.debugDirectoryRva == 0 ||
        info.debugDirectorySize < sizeof(IMAGE_DEBUG_DIRECTORY))
        return;
    const size_t declaredCount = info.debugDirectorySize / sizeof(IMAGE_DEBUG_DIRECTORY);
    const size_t count = std::min(declaredCount, kMaxDebugDirectories);
    for (size_t index = 0; index < count; ++index)
    {
        const uint64_t entryRva = static_cast<uint64_t>(info.debugDirectoryRva) +
            index * sizeof(IMAGE_DEBUG_DIRECTORY);
        IMAGE_DEBUG_DIRECTORY entry{};
        if (!ReadImageExact(processHandle, baseAddress, mappedImageSize, entryRva,
                            &entry, sizeof(entry)))
            break;
        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData == 0 ||
            entry.SizeOfData > sizeof(CodeViewRsdsHeader) + kMaxNameLength)
            continue;
        std::vector<uint8_t> record(entry.SizeOfData);
        if (!ReadImageExact(processHandle, baseAddress, mappedImageSize,
                            entry.AddressOfRawData, record.data(), record.size()))
            continue;
        if (ReadCodeViewRecord(record.data(), record.size(), 0, record.size(), info))
            return;
    }
}

} // namespace openreverse
