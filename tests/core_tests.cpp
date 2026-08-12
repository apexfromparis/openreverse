#include "core/disassembler.h"
#include "core/address_space.h"
#include "core/binary_diff.h"
#include "core/dump_loader.h"
#include "core/offset_model.h"
#include "core/signature_engine.h"
#include "core/analysis_scheduler.h"
#include "core/analysis_database.h"
#include "core/data_analyzer.h"
#include "core/function_analyzer.h"
#include "core/memory_reader.h"
#include "core/module_analyzer.h"
#include "core/pattern_scanner.h"
#include "core/pe_parser.h"
#include "core/process_manager.h"
#include "core/string_scanner.h"
#include "core/xref_scanner.h"
#include "utils/helpers.h"
#include "utils/logger.h"

#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

int failures = 0;
void Expect(bool condition, const char* message);

void TestSharedUtilities()
{
    const auto zero = openreverse::helpers::TryParseAddress("0x0");
    Expect(zero && *zero == 0, "address zero is accepted as a valid address");
    Expect(!openreverse::helpers::TryParseAddress("not-an-address"),
           "invalid address text is rejected explicitly");
    Expect(!openreverse::helpers::TryParseAddress("0x10000000000000000"),
           "overflowing addresses are rejected");

    auto& logger = openreverse::Logger::Get();
    logger.Clear();
    std::thread writer([&logger]() {
        for (int i = 0; i < 200; ++i)
            logger.Log(openreverse::LogLevel::Debug, "snapshot-test-%d", i);
    });
    for (int i = 0; i < 50; ++i)
        (void)logger.Snapshot();
    writer.join();
    Expect(logger.Snapshot().size() == 200, "logger snapshots remain stable during concurrent writes");
    logger.Clear();

    const char evidence[] = "https://example.com/path\0VirtualAlloc\0";
    openreverse::StringScanner scanner;
    const auto strings = scanner.ScanBuffer(reinterpret_cast<const uint8_t*>(evidence), sizeof(evidence),
                                            0x1000, 4, true, false, 10);
    Expect(strings.size() >= 2 && strings[0].category == "URL",
           "URLs are classified as neutral URL evidence");
    Expect(strings.size() >= 2 && strings[1].category == "Process / Memory API",
           "memory APIs are indicators rather than injection verdicts");
}

void Expect(bool condition, const char* message)
{
    if (!condition)
    {
        std::cerr << "FAILED: " << message << '\n';
        ++failures;
    }
}

template<typename T>
void WriteObject(std::vector<uint8_t>& bytes, size_t offset, const T& value)
{
    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

std::vector<uint8_t> BuildMinimalPE64()
{
    std::vector<uint8_t> bytes(0x800, 0);

    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    WriteObject(bytes, 0, dos);

    const size_t ntOffset = static_cast<size_t>(dos.e_lfanew);
    const DWORD signature = IMAGE_NT_SIGNATURE;
    WriteObject(bytes, ntOffset, signature);

    IMAGE_FILE_HEADER file{};
    file.Machine = IMAGE_FILE_MACHINE_AMD64;
    file.NumberOfSections = 2;
    file.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    file.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    WriteObject(bytes, ntOffset + sizeof(DWORD), file);

    IMAGE_OPTIONAL_HEADER64 optional{};
    optional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    optional.AddressOfEntryPoint = 0x1010;
    optional.BaseOfCode = 0x1000;
    optional.ImageBase = 0x140000000ULL;
    optional.SectionAlignment = 0x1000;
    optional.FileAlignment = 0x200;
    optional.SizeOfImage = 0x3000;
    optional.SizeOfHeaders = 0x400;
    optional.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x2000;
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x100;
    WriteObject(bytes, ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), optional);

    const size_t sectionOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(optional);
    IMAGE_SECTION_HEADER text{};
    std::memcpy(text.Name, ".text", 5);
    text.Misc.VirtualSize = 0x300;
    text.VirtualAddress = 0x1000;
    text.SizeOfRawData = 0x200;
    text.PointerToRawData = 0x400;
    text.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    WriteObject(bytes, sectionOffset, text);

    IMAGE_SECTION_HEADER data{};
    std::memcpy(data.Name, ".data", 5);
    data.Misc.VirtualSize = 0x100;
    data.VirtualAddress = 0x2000;
    data.SizeOfRawData = 0x200;
    data.PointerToRawData = 0x600;
    data.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    WriteObject(bytes, sectionOffset + sizeof(IMAGE_SECTION_HEADER), data);

    IMAGE_EXPORT_DIRECTORY exports{};
    exports.Base = 5;
    exports.NumberOfFunctions = 2;
    exports.NumberOfNames = 1;
    exports.AddressOfFunctions = 0x2030;
    exports.AddressOfNames = 0x2040;
    exports.AddressOfNameOrdinals = 0x2048;
    WriteObject(bytes, 0x600, exports);
    const uint32_t functionRvas[] = {0x1010, 0x2070};
    std::memcpy(bytes.data() + 0x630, functionRvas, sizeof(functionRvas));
    const uint32_t exportNameRva = 0x2080;
    WriteObject(bytes, 0x640, exportNameRva);
    const uint16_t namedOrdinalIndex = 0;
    WriteObject(bytes, 0x648, namedOrdinalIndex);
    std::memcpy(bytes.data() + 0x670, "KERNEL32.Sleep", sizeof("KERNEL32.Sleep"));
    std::memcpy(bytes.data() + 0x680, "NamedExport", sizeof("NamedExport"));

    const uint8_t entryCode[] = {0x31, 0xC0, 0xC3};
    std::memcpy(bytes.data() + 0x410, entryCode, sizeof(entryCode));
    bytes[0x750] = 0xA5;
    return bytes;
}

std::vector<uint8_t> BuildPE64WithRuntimeFunctions()
{
    auto bytes = BuildMinimalPE64();
    bytes.resize(0xA00, 0);
    const size_t ntOffset = 0x80;

    IMAGE_FILE_HEADER file{};
    std::memcpy(&file, bytes.data() + ntOffset + sizeof(DWORD), sizeof(file));
    file.NumberOfSections = 3;
    WriteObject(bytes, ntOffset + sizeof(DWORD), file);

    IMAGE_OPTIONAL_HEADER64 optional{};
    const size_t optionalOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    std::memcpy(&optional, bytes.data() + optionalOffset, sizeof(optional));
    optional.SizeOfImage = 0x4000;
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = 0x3000;
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 3 * sizeof(RUNTIME_FUNCTION);
    WriteObject(bytes, optionalOffset, optional);

    const size_t sectionOffset = optionalOffset + sizeof(optional);
    IMAGE_SECTION_HEADER pdata{};
    std::memcpy(pdata.Name, ".pdata", 6);
    pdata.Misc.VirtualSize = 0x200;
    pdata.VirtualAddress = 0x3000;
    pdata.SizeOfRawData = 0x200;
    pdata.PointerToRawData = 0x800;
    pdata.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    WriteObject(bytes, sectionOffset + 2 * sizeof(IMAGE_SECTION_HEADER), pdata);

    const RUNTIME_FUNCTION runtimeFunctions[] = {
        {0x1010, 0x1020, 0x3100},
        {0x1010, 0x1020, 0x3100},
        {0x1020, 0x1030, 0x3104}
    };
    std::memcpy(bytes.data() + 0x800, runtimeFunctions, sizeof(runtimeFunctions));
    const uint8_t firstFunction[] = {
        0x48, 0x8B, 0x05, 0xE9, 0x0F, 0x00, 0x00,
        0x48, 0x8B, 0xD9,
        0x8B, 0x43, 0x20,
        0x90, 0x90, 0xC3
    };
    const uint8_t secondFunction[] = {
        0x89, 0x53, 0x24, 0x31, 0xC0, 0xC3
    };
    std::memcpy(bytes.data() + 0x410, firstFunction, sizeof(firstFunction));
    std::memcpy(bytes.data() + 0x420, secondFunction, sizeof(secondFunction));
    return bytes;
}

void TestPEMapping()
{
    auto raw = BuildMinimalPE64();
    openreverse::PEParser parser;
    const auto info = parser.ParseBuffer(raw.data(), raw.size());

    Expect(info.valid, "valid PE64 fixture parses");
    Expect(info.is64bit, "PE64 fixture is recognized as 64-bit");
    Expect(info.sections.size() == 2, "both section headers are parsed");
    Expect(info.sizeOfHeaders == 0x400, "SizeOfHeaders is retained");
    Expect(info.exports.size() == 2, "named and ordinal-only exports are retained");
    if (info.exports.size() == 2)
    {
        Expect(info.exports[0].name == "NamedExport" && !info.exports[0].isForwarder,
               "named code export is parsed");
        Expect(info.exports[1].name == "Ordinal#6" && info.exports[1].isForwarder &&
               info.exports[1].forwarder == "KERNEL32.Sleep",
               "ordinal-only forwarded export is distinguished from code");
    }

    size_t offset = 0;
    Expect(openreverse::PEParser::RvaToFileOffset(0x1010, 3, info, raw.size(), offset) && offset == 0x410,
           "RVA in .text maps through PointerToRawData");
    Expect(openreverse::PEParser::RvaToFileOffset(0x100, 1, info, raw.size(), offset) && offset == 0x100,
           "header RVA maps directly inside SizeOfHeaders");
    Expect(!openreverse::PEParser::RvaToFileOffset(0x1250, 1, info, raw.size(), offset),
           "virtual zero-fill does not map to unrelated raw bytes");
    Expect(openreverse::PEParser::RvaToFileOffset(0x2150, 1, info, raw.size(), offset) && offset == 0x750,
           "disk-backed raw tail maps when RawSize exceeds VirtualSize");

    std::vector<uint8_t> image;
    Expect(openreverse::PEParser::BuildMappedImage(raw, info, image), "valid PE builds an RVA-mapped image");
    Expect(image.size() == 0x3000, "mapped image uses SizeOfImage");
    Expect(image[0x1010] == 0x31 && image[0x1012] == 0xC3, "mapped .text bytes are at their RVA");
    Expect(image[0x1250] == 0, "virtual section tail remains zero-filled");
    Expect(image[0x2150] == 0xA5, "raw section tail remains available in mapped image");

    openreverse::MemoryReader reader;
    reader.SetOfflineBuffer(&image, info.imageBase);
    uint8_t code[3]{};
    Expect(reader.ReadMemory(nullptr, info.imageBase + 0x1010, code, sizeof(code)) &&
           code[0] == 0x31 && code[2] == 0xC3,
           "offline MemoryReader reads mapped bytes by VA");
    Expect(!reader.ReadMemory(nullptr, 0x1010, code, sizeof(code)),
           "offline MemoryReader rejects ambiguous raw/RVA addresses");
}

void TestAddressSpacesAndRuntimeFunctions()
{
    auto raw = BuildPE64WithRuntimeFunctions();
    openreverse::PEParser parser;
    const auto pe = parser.ParseBuffer(raw.data(), raw.size());
    Expect(pe.valid && pe.runtimeFunctions.size() == 2 && pe.rejectedRuntimeFunctionCount == 1,
           "x64 runtime functions retain valid unique non-overlapping ranges");
    Expect(pe.runtimeFunctionDirectoryComplete,
           "complete runtime-function directory is reported as complete");

    openreverse::PEFileAddressSpace fileSpace(raw, pe);
    size_t sourceOffset = 0;
    Expect(fileSpace.ResolveRva(0x1010, 3, sourceOffset) && sourceOffset == 0x410,
           "raw PE address space resolves RVA through section raw offsets");

    std::vector<uint8_t> mapped;
    Expect(openreverse::PEParser::BuildMappedImage(raw, pe, mapped),
           "runtime-function fixture maps to an image");
    openreverse::MappedImageAddressSpace mappedSpace(mapped, pe.imageBase);
    Expect(mappedSpace.ResolveRva(0x1010, 3, sourceOffset) && sourceOffset == 0x1010,
           "mapped image address space resolves RVA directly");
    openreverse::DumpAddressSpace dumpSpace(mapped, 0x180000000ULL);
    uint32_t dumpRva = 0;
    Expect(dumpSpace.VaToRva(0x180001010ULL, dumpRva) && dumpRva == 0x1010,
           "dump address space retains its explicit image base");

    const auto mappedPe = parser.ParseMappedImage(mapped.data(), mapped.size(), 0x180000000ULL);
    Expect(mappedPe.valid && mappedPe.imageBase == 0x180000000ULL &&
           mappedPe.runtimeFunctions.size() == 2 && mappedPe.exports.size() == 2,
           "mapped PE image parses directories without raw-file translation");

    auto truncated = raw;
    IMAGE_OPTIONAL_HEADER64 optional{};
    const size_t optionalOffset = 0x80 + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    std::memcpy(&optional, truncated.data() + optionalOffset, sizeof(optional));
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = sizeof(RUNTIME_FUNCTION) + 1;
    WriteObject(truncated, optionalOffset, optional);
    const auto truncatedPe = parser.ParseBuffer(truncated.data(), truncated.size());
    Expect(truncatedPe.valid && !truncatedPe.runtimeFunctionDirectoryComplete &&
           truncatedPe.runtimeFunctions.size() == 1,
           "truncated runtime-function directory is explicit and bounded");
}

void TestMappedAnalysisPipeline()
{
    auto raw = BuildPE64WithRuntimeFunctions();
    openreverse::PEParser parser;
    const auto pe = parser.ParseBuffer(raw.data(), raw.size());
    std::vector<uint8_t> mapped;
    openreverse::PEParser::BuildMappedImage(raw, pe, mapped);
    openreverse::ModuleInfo module{"pipeline.exe", "pipeline.exe", pe.imageBase, pe.sizeOfImage};
    openreverse::ModuleAnalyzer analyzer;
    const auto analysis = analyzer.AnalyzeMappedImage(mapped, raw.size(), module, pe);
    const auto runtimeFunction = std::find_if(analysis.functions.begin(), analysis.functions.end(),
        [&](const openreverse::FunctionInfo& function) {
            return function.startAddress == pe.imageBase + 0x1010;
        });
    Expect(analysis.success && runtimeFunction != analysis.functions.end() &&
           runtimeFunction->source == openreverse::FunctionSource::RuntimeFunction &&
           runtimeFunction->boundaryKnown && runtimeFunction->size == 0x10,
           "mapped analysis prioritizes .pdata and retains exact function boundaries");
    Expect(!analysis.xrefs.empty() && analysis.xrefs.front().toAddress == pe.imageBase + 0x2000 &&
           analysis.xrefs.front().functionAddress == pe.imageBase + 0x1010,
           "mapped analysis indexes operand Xrefs with containing-function provenance");
    const auto copiedField = std::find_if(analysis.fieldAccesses.begin(), analysis.fieldAccesses.end(),
        [](const openreverse::FieldAccessCandidate& field) {
            return field.offset == 0x20 && field.argumentIndex == 1;
        });
    Expect(copiedField != analysis.fieldAccesses.end() &&
           copiedField->originRegister == "rcx" && copiedField->baseRegister == "rbx",
           "mapped analysis carries register-origin evidence into field records");
    Expect(!analysis.offsets.empty() && !analysis.identity.sha256.empty() &&
           !analysis.signatures.empty(),
           "mapped analysis publishes typed offsets, module identity, and signatures together");
}

void TestMalformedPEs()
{
    openreverse::PEParser parser;

    std::vector<uint8_t> truncated(sizeof(IMAGE_DOS_HEADER), 0);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x40;
    WriteObject(truncated, 0, dos);
    Expect(!parser.ParseBuffer(truncated.data(), truncated.size()).valid, "truncated NT headers fail closed");

    auto negativeOffset = BuildMinimalPE64();
    std::memcpy(&dos, negativeOffset.data(), sizeof(dos));
    dos.e_lfanew = -1;
    WriteObject(negativeOffset, 0, dos);
    Expect(!parser.ParseBuffer(negativeOffset.data(), negativeOffset.size()).valid, "negative e_lfanew is rejected");

    auto shortOptional = BuildMinimalPE64();
    const size_t fileHeaderOffset = 0x80 + sizeof(DWORD);
    IMAGE_FILE_HEADER file{};
    std::memcpy(&file, shortOptional.data() + fileHeaderOffset, sizeof(file));
    file.SizeOfOptionalHeader = sizeof(uint16_t);
    WriteObject(shortOptional, fileHeaderOffset, file);
    Expect(!parser.ParseBuffer(shortOptional.data(), shortOptional.size()).valid,
           "undersized optional header is rejected");

    auto badSection = BuildMinimalPE64();
    const size_t sectionOffset = 0x80 + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
    IMAGE_SECTION_HEADER section{};
    std::memcpy(&section, badSection.data() + sectionOffset, sizeof(section));
    section.PointerToRawData = static_cast<DWORD>(badSection.size() - 1);
    section.SizeOfRawData = 0x200;
    WriteObject(badSection, sectionOffset, section);
    Expect(!parser.ParseBuffer(badSection.data(), badSection.size()).valid,
           "section raw range outside the file is rejected");

    auto unsupportedMachine = BuildMinimalPE64();
    std::memcpy(&file, unsupportedMachine.data() + fileHeaderOffset, sizeof(file));
    file.Machine = IMAGE_FILE_MACHINE_ARM64;
    WriteObject(unsupportedMachine, fileHeaderOffset, file);
    Expect(!parser.ParseBuffer(unsupportedMachine.data(), unsupportedMachine.size()).valid,
           "unsupported machine and optional-header combinations are rejected");

    auto overflowingImage = BuildMinimalPE64();
    const size_t optionalOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
    IMAGE_OPTIONAL_HEADER64 optional{};
    std::memcpy(&optional, overflowingImage.data() + optionalOffset, sizeof(optional));
    optional.ImageBase = (std::numeric_limits<uint64_t>::max)() - optional.SizeOfImage + 1;
    WriteObject(overflowingImage, optionalOffset, optional);
    Expect(!parser.ParseBuffer(overflowingImage.data(), overflowingImage.size()).valid,
           "image VA range overflow is rejected");

    auto invalidForwarder = BuildMinimalPE64();
    IMAGE_SECTION_HEADER dataSection{};
    std::memcpy(&dataSection, invalidForwarder.data() + sectionOffset + sizeof(IMAGE_SECTION_HEADER),
                sizeof(dataSection));
    dataSection.SizeOfRawData = 0xA0;
    WriteObject(invalidForwarder, sectionOffset + sizeof(IMAGE_SECTION_HEADER), dataSection);
    const uint32_t invalidForwarderRva = 0x20F0;
    WriteObject(invalidForwarder, 0x634, invalidForwarderRva);
    const auto invalidForwarderInfo = parser.ParseBuffer(invalidForwarder.data(), invalidForwarder.size());
    Expect(invalidForwarderInfo.valid && invalidForwarderInfo.exports.size() == 1,
           "virtual-only forwarder strings are not fabricated from file offset zero");
}

void TestBuiltExecutablePE()
{
    char executablePath[MAX_PATH]{};
    Expect(GetModuleFileNameA(nullptr, executablePath, MAX_PATH) != 0,
           "test executable path is available");

    openreverse::PEParser parser;
    std::vector<uint8_t> raw;
    const auto info = parser.ParseFile(executablePath, raw);
    Expect(info.valid && !raw.empty(), "the MSVC-built test executable parses as a PE file");

    std::vector<uint8_t> image;
    Expect(openreverse::PEParser::BuildMappedImage(raw, info, image),
           "the MSVC-built test executable maps for offline analysis");
    Expect(info.entryPoint < image.size(), "the built executable entry point is inside the mapped image");
}

void TestLiveExecutableSections()
{
    MODULEINFO moduleInfo{};
    HMODULE module = GetModuleHandleW(nullptr);
    Expect(module != nullptr && GetModuleInformation(GetCurrentProcess(), module, &moduleInfo, sizeof(moduleInfo)),
           "current test module information is available");
    if (!module || moduleInfo.SizeOfImage == 0)
        return;

    const uint64_t base = reinterpret_cast<uint64_t>(moduleInfo.lpBaseOfDll);
    openreverse::PEParser parser;
    const auto pe = parser.Parse(GetCurrentProcess(), base, moduleInfo.SizeOfImage);
    Expect(pe.valid, "bounded live PE parser accepts the current test module");
    Expect(!parser.Parse(GetCurrentProcess(), base, sizeof(IMAGE_DOS_HEADER)).valid,
           "bounded live PE parser rejects a truncated module range");

    const auto executable = std::find_if(pe.sections.begin(), pe.sections.end(), [](const auto& section) {
        return (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
            std::max(section.virtualSize, section.rawDataSize) != 0;
    });
    Expect(executable != pe.sections.end(), "live PE exposes an executable section");
    if (executable == pe.sections.end())
        return;

    const uint64_t sectionSize = std::max<uint64_t>(executable->virtualSize, executable->rawDataSize);
    openreverse::MemoryReader reader;
    const auto report = reader.ReadReadableBlocks(GetCurrentProcess(), base + executable->virtualAddress,
                                                   sectionSize, 4096);
    Expect(!report.blocks.empty() && report.bytesRead > 0, "live executable section yields readable blocks");
    Expect(report.bytesRead <= 4096, "live executable read respects its byte budget");
    for (const auto& block : report.blocks)
    {
        Expect(block.baseAddress >= base + executable->virtualAddress,
               "live readable block starts inside the executable section");
        Expect(block.bytes.size() <= sectionSize - (block.baseAddress - (base + executable->virtualAddress)),
                "live readable block remains inside the executable section");
    }

    openreverse::ModuleInfo currentModule{"OpenReverseCoreTests.exe", "", base, moduleInfo.SizeOfImage};
    openreverse::ModuleAnalysisOptions options;
    options.maxCodeBytes = 256 * 1024;
    options.maxStringBytes = 64 * 1024;
    options.maxInstructions = 4096;
    options.maxFunctions = 100;
    options.maxStrings = 100;
    options.maxDuration = std::chrono::seconds(5);
    openreverse::ModuleAnalyzer analyzer;
    const auto analysis = analyzer.AnalyzeLive(GetCurrentProcess(), currentModule, true, options);
    Expect(analysis.success && analysis.codeBytesAnalyzed <= options.maxCodeBytes &&
           analysis.stringBytesAnalyzed <= options.maxStringBytes,
           "bounded live module analysis completes on the current test executable");

    openreverse::CancellationSource cancellation;
    cancellation.Cancel();
    const auto cancellationToken = cancellation.Token();
    const auto cancelled = analyzer.AnalyzeLive(GetCurrentProcess(), currentModule, true, options,
                                                &cancellationToken);
    Expect(cancelled.cancelled && !cancelled.success,
           "live module analysis honors cancellation before executable scanning");
}

void TestDecodedFunctionCalls()
{
    const uint64_t base = 0x140001000ULL;
    std::vector<uint8_t> code(32, 0x90);
    const uint8_t instructions[] = {
        0xB8, 0xE8, 0x00, 0x00, 0x00, // mov eax, 0xE8: not a CALL
        0xE8, 0x02, 0x00, 0x00, 0x00, // call base+0x0C
        0xC3,
        0x90,
        0x90, 0x31, 0xC0,
        0xC3
    };
    std::memcpy(code.data(), instructions, sizeof(instructions));

    openreverse::FunctionAnalyzer analyzer;
    const auto functions = analyzer.DiscoverFunctions(code.data(), code.size(), base, true);
    const auto hasAddress = [&](uint64_t address) {
        return std::any_of(functions.begin(), functions.end(), [address](const openreverse::FunctionInfo& function) {
            return function.startAddress == address;
        });
    };
    Expect(hasAddress(base + 0x0C), "decoded direct CALL target is discovered");
    Expect(!hasAddress(base + 1), "0xE8 inside an immediate does not create a function");
}

bool HasCFGEdge(const openreverse::ControlFlowGraph& cfg, uint64_t source, uint64_t target,
                openreverse::CFGEdgeType type)
{
    return std::any_of(cfg.edges.begin(), cfg.edges.end(), [&](const openreverse::CFGEdge& edge) {
        return edge.source == source && edge.target == target && edge.type == type;
    });
}

openreverse::FunctionInfo AnalyzeCFG(const std::vector<uint8_t>& code, uint64_t base = 0x140010000ULL,
                                     size_t instructionBudget = 4096)
{
    openreverse::Disassembler disassembler;
    Expect(disassembler.Init(true), "Capstone initializes for CFG test");
    openreverse::FunctionAnalyzer analyzer;
    return analyzer.AnalyzeFunction(code.data(), code.size(), base, base, disassembler, true,
                                    code.size(), instructionBudget);
}

void TestRecursiveCFG()
{
    const uint64_t base = 0x140010000ULL;

    {
        const auto function = AnalyzeCFG({0x90, 0x90, 0xC3}, base);
        Expect(function.cfg.basicBlocks.size() == 1, "linear function has one block");
        if (!function.cfg.basicBlocks.empty())
            Expect(function.cfg.basicBlocks[0].startAddress == base && function.cfg.basicBlocks[0].endAddress == base + 3,
                   "linear block has the expected half-open range");
        Expect(HasCFGEdge(function.cfg, base, 0, openreverse::CFGEdgeType::Return),
               "linear return emits a Return edge");
        Expect(function.cfg.basicBlocks[0].successors.empty() && function.cfg.basicBlocks[0].predecessors.empty(),
               "linear return block has no CFG neighbors");
        openreverse::FunctionAnalyzer analyzer;
        const std::string summary = analyzer.GenerateAssemblySummary(function, true);
        Expect(summary.find("nop") != std::string::npos &&
               summary.find("Every instruction below is decoded evidence") != std::string::npos &&
               summary.find("rax_result") == std::string::npos &&
               summary.find("_condition") == std::string::npos,
               "assembly summary reports decoded evidence without invented source semantics");
    }

    {
        const std::vector<uint8_t> code = {
            0x85, 0xC9,                         // test ecx, ecx
            0x74, 0x07,                         // je +0x0B
            0xB8, 0x01, 0x00, 0x00, 0x00,       // mov eax, 1
            0xEB, 0x05,                         // jmp +0x10
            0xB8, 0x02, 0x00, 0x00, 0x00,       // mov eax, 2
            0xC3                                // ret
        };
        const auto function = AnalyzeCFG(code, base);
        Expect(function.cfg.basicBlocks.size() == 4, "if/else diamond has four blocks");
        Expect(HasCFGEdge(function.cfg, base, base + 0x0B, openreverse::CFGEdgeType::ConditionalTrue),
               "if/else taken edge is typed ConditionalTrue");
        Expect(HasCFGEdge(function.cfg, base, base + 4, openreverse::CFGEdgeType::ConditionalFalse),
               "if/else fallthrough edge is typed ConditionalFalse");
        Expect(HasCFGEdge(function.cfg, base + 4, base + 0x10, openreverse::CFGEdgeType::Unconditional),
               "if branch joins through an unconditional edge");
        Expect(HasCFGEdge(function.cfg, base + 0x0B, base + 0x10, openreverse::CFGEdgeType::Fallthrough),
               "else branch joins through a fallthrough edge");
        const auto* join = function.cfg.FindBlock(base + 0x10);
        Expect(join && join->predecessors.size() == 2, "if/else join records both predecessors");
        Expect(function.cyclomaticComplexity == 2, "if/else has complexity two");
    }

    {
        const auto function = AnalyzeCFG({
            0x85, 0xC9,                         // test ecx, ecx
            0x74, 0x05,                         // je return
            0xB8, 0x01, 0x00, 0x00, 0x00,       // mov eax, 1
            0xC3                                // ret
        }, base);
        Expect(function.cfg.basicBlocks.size() == 3, "if without else has condition, body, and return blocks");
        Expect(HasCFGEdge(function.cfg, base + 4, base + 9, openreverse::CFGEdgeType::Fallthrough),
               "if body falls through to the shared return");
    }

    {
        const auto function = AnalyzeCFG({0xE2, 0xFE, 0xC3}, base); // loop self; ret
        Expect(function.cfg.basicBlocks.size() == 2, "loop has loop and exit blocks");
        Expect(HasCFGEdge(function.cfg, base, base, openreverse::CFGEdgeType::ConditionalTrue),
               "loop instruction creates a backward self-edge");
        Expect(HasCFGEdge(function.cfg, base, base + 2, openreverse::CFGEdgeType::ConditionalFalse),
               "loop instruction preserves its exit edge");
        const auto* loop = function.cfg.FindBlock(base);
        Expect(loop && loop->successors.size() == 2 && loop->predecessors.size() == 1,
               "loop block has deterministic successors and predecessor");
    }

    {
        const std::vector<uint8_t> code = {
            0x85, 0xC9, 0x74, 0x0C,             // outer if -> +0x10
            0x85, 0xD2, 0x74, 0x04,             // nested if -> +0x0C
            0xB0, 0x01, 0xEB, 0x06,             // value 1 -> +0x12
            0xB0, 0x02, 0xEB, 0x02,             // value 2 -> +0x12
            0xB0, 0x03,                         // value 3
            0xC3                                // join
        };
        const auto function = AnalyzeCFG(code, base);
        Expect(function.cfg.basicBlocks.size() == 6, "nested branches produce six reachable blocks");
        Expect(function.cyclomaticComplexity == 3, "two nested decisions produce complexity three");
        const auto* join = function.cfg.FindBlock(base + 0x12);
        Expect(join && join->predecessors.size() == 3, "nested branch join records three predecessors");
    }

    {
        const auto function = AnalyzeCFG({0x90, 0xEB, 0xFD}, base); // nop; jmp entry
        Expect(function.cfg.basicBlocks.size() == 1, "backward unconditional jump does not duplicate blocks");
        Expect(HasCFGEdge(function.cfg, base, base, openreverse::CFGEdgeType::Unconditional),
               "backward unconditional jump creates a self-edge");
        Expect(function.cfg.decodedInstructionCount == 2, "backward jump terminates traversal without looping");
    }

    {
        const auto function = AnalyzeCFG({0xEB, 0x03, 0x90, 0x90, 0x90, 0xC3}, base);
        Expect(function.cfg.basicBlocks.size() == 2, "unconditional jump excludes skipped unreachable bytes");
        Expect(function.cfg.FindContainingBlock(base + 2) == nullptr,
               "unreachable bytes are absent from the CFG");
        Expect(HasCFGEdge(function.cfg, base, base + 5, openreverse::CFGEdgeType::Unconditional),
               "unconditional jump targets the reachable return block");
    }

    {
        const auto function = AnalyzeCFG({0x85, 0xC9, 0x74, 0x01, 0xC3, 0xC3, 0x90, 0xC3}, base);
        Expect(function.cfg.basicBlocks.size() == 3, "early return keeps only reachable return paths");
        Expect(function.analyzedEndAddress == base + 6,
               "early-return CFG excludes a later unreachable return from analyzed extent");
    }

    {
        const auto function = AnalyzeCFG({0xEB, 0x01, 0x90, 0x0F}, base);
        Expect(function.cfg.basicBlocks.size() == 1, "invalid internal branch target creates no fake block");
        Expect(HasCFGEdge(function.cfg, base, base + 3, openreverse::CFGEdgeType::Unconditional),
               "invalid internal target remains explicit on the source edge");
        Expect(!function.cfg.complete, "decode failure marks CFG incomplete");
    }

    {
        const auto function = AnalyzeCFG({0x75, 0x7F, 0xC3}, base);
        Expect(function.cfg.basicBlocks.size() == 2, "external branch target is not decoded as an internal block");
        Expect(HasCFGEdge(function.cfg, base, base + 0x81, openreverse::CFGEdgeType::ConditionalTrue),
               "external branch target remains visible as an edge");
        Expect(function.cfg.FindBlock(base + 0x81) == nullptr, "external branch has no internal basic block");
        Expect(function.cfg.complete, "external transfer does not imply malformed decoding");
    }

    {
        const auto function = AnalyzeCFG({0x0F}, base);
        Expect(function.cfg.basicBlocks.empty() && !function.cfg.complete,
               "truncated instruction stream fails safely without blocks");
    }

    {
        const auto function = AnalyzeCFG({0x90, 0x90, 0x90, 0xC3}, base, 2);
        Expect(function.cfg.instructionBudgetReached && !function.cfg.complete,
               "instruction budget truncates CFG explicitly");
        Expect(function.cfg.decodedInstructionCount == 2, "instruction budget is enforced exactly");
    }

    {
        const auto function = AnalyzeCFG({0x90, 0xC3}, base, 2);
        Expect(function.cfg.complete && !function.cfg.instructionBudgetReached,
               "a return at the exact instruction budget completes the CFG");
    }

    {
        const auto function = AnalyzeCFG({0x75, 0x03, 0xB8, 0x00, 0x00, 0x90, 0x00, 0x00, 0xC3}, base);
        Expect(!function.cfg.complete, "a branch into another instruction marks the CFG incomplete");
        Expect(function.cfg.FindContainingBlock(base + 2) == nullptr,
               "overlapping instruction paths do not create overlapping basic blocks");
    }
}

void TestTypedXRefs()
{
    const uint64_t base = 0x140002000ULL;
    const uint8_t code[] = {
        0xB8, 0x78, 0x56, 0x34, 0x12,       // mov eax, 0x12345678
        0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, // mov rax, [rip+0x10]
        0x48, 0x89, 0x05, 0x20, 0x00, 0x00, 0x00, // mov [rip+0x20], rax
        0x48, 0x8D, 0x05, 0x30, 0x00, 0x00, 0x00, // lea rax, [rip+0x30]
        0x48, 0x83, 0x05, 0x40, 0x00, 0x00, 0x00, 0x01, // add qword ptr [rip+0x40], 1
        0xC3
    };

    openreverse::Disassembler disassembler;
    Expect(disassembler.Init(true), "Capstone initializes for x64 Xref test");
    openreverse::XRefScanner scanner;
    scanner.ScanBuffer(code, sizeof(code), base, "fixture", disassembler, true);
    const auto& refs = scanner.GetAllEntries();
    Expect(refs.size() == 4, "ordinary immediate constants are excluded from Xrefs");
    if (refs.size() == 4)
    {
        Expect(refs[0].toAddress == base + 0x1C && refs[0].type == openreverse::XRefType::Read,
               "RIP-relative source operand is a READ Xref");
        Expect(refs[0].operandIndex == 1 && refs[0].operandSize == 8,
               "Xref retains source operand index and width");
        Expect(refs[1].toAddress == base + 0x33 && refs[1].type == openreverse::XRefType::Write,
               "RIP-relative destination operand is a WRITE Xref");
        Expect(refs[2].toAddress == base + 0x4A && refs[2].type == openreverse::XRefType::Address,
                "RIP-relative LEA is retained as address generation");
        Expect(refs[3].toAddress == base + 0x62 && refs[3].type == openreverse::XRefType::ReadWrite,
               "read-modify-write memory operands retain both access modes");
    }
}

void TestPatternParsing()
{
    const auto pattern = openreverse::PatternScanner::ParsePattern("48 8B ?? FF");
    Expect(pattern.size() == 4 && pattern[2].wildcard && !pattern[3].wildcard && pattern[3].value == 0xFF,
           "valid patterns preserve wildcards and literal FF bytes");
    Expect(openreverse::PatternScanner::ParsePattern("GG").empty(), "non-hex pattern tokens are rejected");
    Expect(openreverse::PatternScanner::ParsePattern("100").empty(), "oversized pattern tokens are rejected");
    Expect(openreverse::PatternScanner::ParsePattern("4Z").empty(), "partially valid hex tokens are rejected");

    std::string oversized;
    for (size_t i = 0; i < 4097; ++i) oversized += "90 ";
    Expect(openreverse::PatternScanner::ParsePattern(oversized).empty(),
           "absurdly large patterns are rejected during parsing");
    Expect(openreverse::PatternScanner::AdvanceAfterRead(2, 8) == 2,
           "partial reads smaller than the pattern cannot underflow scan advancement");
    Expect(openreverse::PatternScanner::AdvanceAfterRead(8, 8) == 1,
           "pattern-sized reads retain the required overlap");
    Expect(openreverse::PatternScanner::AdvanceAfterRead(0, 8) == 0,
           "zero-byte reads stop chunk scanning");
}

void TestOfflinePatternScanning()
{
    auto raw = BuildMinimalPE64();
    openreverse::PEParser parser;
    const auto pe = parser.ParseBuffer(raw.data(), raw.size());
    std::vector<uint8_t> image;
    Expect(openreverse::PEParser::BuildMappedImage(raw, pe, image),
           "offline pattern fixture maps successfully");
    if (image.empty()) return;

    const uint8_t signatureA[] = {0x48, 0x8B, 0x11, 0x22, 0x33, 0x48, 0x85, 0xC0};
    const uint8_t signatureB[] = {0x48, 0x8B, 0x44, 0x55, 0x66, 0x48, 0x85, 0xC0};
    std::memcpy(image.data() + 0x1100, signatureA, sizeof(signatureA));
    std::memcpy(image.data() + 0x1120, signatureB, sizeof(signatureB));
    std::memcpy(image.data() + 0x2100, signatureA, sizeof(signatureA));
    image[0x1250] = 0xDE;
    image[0x1251] = 0xAD;
    image[0x11FE] = 0xAA;
    image[0x11FF] = 0xBB;
    image[0x2000] = 0xCC;
    image[0x2001] = 0xDD;

    openreverse::PatternScanner scanner;
    openreverse::OfflinePatternScanOptions options;
    options.patternIdentifier = "fixture-signature";
    const auto wildcard = openreverse::PatternScanner::ParsePattern("48 8B ? ? ? 48 85 C0");
    auto report = scanner.ScanOffline(wildcard, image, pe, raw.size(), options);
    Expect(report.error.empty() && report.results.size() == 2,
           "default offline scan finds wildcard matches only in executable sections");
    if (report.results.size() == 2)
    {
        Expect(report.results[0].address == pe.imageBase + 0x1100 && report.results[0].rva == 0x1100,
               "offline result reports the correct VA and RVA");
        Expect(report.results[0].hasRawOffset && report.results[0].rawOffset == 0x500,
               "offline initialized result reports its raw file offset");
        Expect(report.results[0].sectionName == ".text" &&
               report.results[0].patternIdentifier == "fixture-signature",
               "offline result retains section and pattern metadata");
    }

    options.scope = openreverse::OfflinePatternScanScope::AllMappedRegions;
    report = scanner.ScanOffline(wildcard, image, pe, raw.size(), options);
    Expect(report.results.size() == 3, "all mapped regions include executable and data matches");

    options.scope = openreverse::OfflinePatternScanScope::SpecificSection;
    options.sectionName = ".data";
    report = scanner.ScanOffline(wildcard, image, pe, raw.size(), options);
    Expect(report.results.size() == 1 && report.results[0].sectionName == ".data",
           "specific-section scope excludes matches from other sections");

    options.scope = openreverse::OfflinePatternScanScope::ExecutableSections;
    const auto exact = openreverse::PatternScanner::ParsePattern("48 8B 11 22 33 48 85 C0");
    report = scanner.ScanOffline(exact, image, pe, raw.size(), options);
    Expect(report.results.size() == 1 && report.results[0].rva == 0x1100,
           "exact offline pattern produces one deterministic match");

    const auto absent = openreverse::PatternScanner::ParsePattern("FE ED FA CE");
    report = scanner.ScanOffline(absent, image, pe, raw.size(), options);
    Expect(report.results.empty(), "offline scanner reports zero matches without fake success");

    const auto crossBoundary = openreverse::PatternScanner::ParsePattern("AA BB CC DD");
    options.scope = openreverse::OfflinePatternScanScope::AllMappedRegions;
    report = scanner.ScanOffline(crossBoundary, image, pe, raw.size(), options);
    Expect(report.results.empty(), "offline scanner never joins bytes across PE range boundaries");

    const auto virtualOnly = openreverse::PatternScanner::ParsePattern("DE AD");
    report = scanner.ScanOffline(virtualOnly, image, pe, raw.size(), options);
    Expect(report.results.size() == 1 && !report.results[0].hasRawOffset,
           "mapped virtual-tail match is not assigned a fake raw offset");

    std::vector<openreverse::PatternByte> tooLarge(0x201, {0x90, false});
    options.scope = openreverse::OfflinePatternScanScope::SpecificSection;
    options.sectionName = ".data";
    report = scanner.ScanOffline(tooLarge, image, pe, raw.size(), options);
    Expect(report.results.empty(), "pattern larger than a scan section is rejected without underflow");

    openreverse::CancellationSource cancellation;
    cancellation.Cancel();
    const auto cancellationToken = cancellation.Token();
    options.scope = openreverse::OfflinePatternScanScope::AllMappedRegions;
    report = scanner.ScanOffline(exact, image, pe, raw.size(), options, &cancellationToken);
    Expect(report.results.empty() && report.bytesScanned == 0,
           "offline pattern cancellation does not report unscanned bytes");
}

void TestAnalysisScheduler()
{
    openreverse::AnalysisScheduler scheduler;
    int published = 0;
    const uint64_t completedJob = scheduler.Submit("completion-test",
        [](const openreverse::CancellationToken& cancellation,
           const openreverse::AnalysisScheduler::ProgressCallback& progress) {
            if (cancellation.IsCancellationRequested())
                return openreverse::AnalysisScheduler::Completion{};
            progress(0.5f);
            return openreverse::AnalysisScheduler::Completion{};
        });

    // Submit a second job whose completion must only run when the caller drains it.
    const uint64_t publishJob = scheduler.Submit("publish-test",
        [&published](const openreverse::CancellationToken&,
                     const openreverse::AnalysisScheduler::ProgressCallback& progress) {
            progress(1.0f);
            return openreverse::AnalysisScheduler::Completion([&published] { ++published; });
        });

    for (int i = 0; i < 100; ++i)
    {
        const auto first = scheduler.GetJob(completedJob);
        const auto second = scheduler.GetJob(publishJob);
        if (first.state == openreverse::AnalysisJobState::Completed &&
            second.state == openreverse::AnalysisJobState::Completed)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    Expect(published == 0, "analysis completion is not published from the worker thread");
    scheduler.DrainCompletions();
    Expect(published == 1, "analysis completion is published when the owner drains completions");

    auto capturedResource = std::make_shared<int>(42);
    std::weak_ptr<int> releasedResource = capturedResource;
    const uint64_t releaseJob = scheduler.Submit("resource-release-test",
        [capturedResource](const openreverse::CancellationToken&,
                           const openreverse::AnalysisScheduler::ProgressCallback&) {
            return openreverse::AnalysisScheduler::Completion{};
        });
    capturedResource.reset();
    for (int i = 0; i < 100 &&
         scheduler.GetJob(releaseJob).state != openreverse::AnalysisJobState::Completed; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    Expect(releasedResource.expired(), "completed jobs release captured worker resources");

    const uint64_t failingCompletion = scheduler.Submit("completion-failure-test",
        [](const openreverse::CancellationToken&,
           const openreverse::AnalysisScheduler::ProgressCallback&) {
            return openreverse::AnalysisScheduler::Completion([] { throw std::runtime_error("publish failed"); });
        });
    for (int i = 0; i < 100 &&
         scheduler.GetJob(failingCompletion).state != openreverse::AnalysisJobState::Completed; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    scheduler.DrainCompletions();
    Expect(scheduler.GetJob(failingCompletion).state == openreverse::AnalysisJobState::Failed,
           "completion exceptions are reported as failed jobs");

    std::atomic<bool> started{false};
    const uint64_t cancellable = scheduler.Submit("cancel-test",
        [&started](const openreverse::CancellationToken& cancellation,
                   const openreverse::AnalysisScheduler::ProgressCallback& progress) {
            started.store(true);
            while (!cancellation.IsCancellationRequested())
            {
                progress(0.25f);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            return openreverse::AnalysisScheduler::Completion{};
        });
    for (int i = 0; i < 100 && !started.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    Expect(started.load(), "scheduler cancellation test reaches the running state");
    scheduler.Cancel(cancellable);
    scheduler.CancelAllAndWait();
    Expect(scheduler.GetJob(cancellable).state == openreverse::AnalysisJobState::Cancelled,
           "analysis cancellation stops an active job and joins safely");
    scheduler.Shutdown();
}

void TestAnalysisDatabase()
{
    openreverse::AnalysisDatabase database;
    openreverse::ModuleInfo module{"fixture.exe", "fixture.exe", 0x140000000ULL, 0x3000};
    openreverse::PEInfo pe;
    pe.valid = true;

    openreverse::FunctionInfo first;
    first.startAddress = module.baseAddress + 0x1000;
    first.endAddress = first.startAddress + 0x40;
    first.size = 0x40;
    first.boundaryKnown = true;
    first.name = "first";
    openreverse::XRefEntry firstXref;
    firstXref.fromAddress = first.startAddress + 4;
    firstXref.toAddress = module.baseAddress + 0x2000;
    openreverse::StringResult firstString{module.baseAddress + 0x2000, "alpha",
        openreverse::StringEncoding::ASCII, 5};

    const uint64_t initialRevision = database.ReplaceModuleAnalysis(
        module, true, pe, {first}, {firstXref}, {firstString});
    const auto* initial = database.GetModule(module.baseAddress);
    Expect(initial && initial->functions.size() == 1 && initial->xrefs.size() == 1 && initial->strings.size() == 1,
           "analysis database publishes a complete module result");
    Expect(database.FindModuleContaining(module.baseAddress + module.size - 1) == initial &&
           database.FindModuleContaining(module.baseAddress + module.size) == nullptr,
           "analysis database resolves addresses with an exclusive module end");
    Expect(database.FindFunction(module.baseAddress, first.startAddress) != nullptr &&
           database.FindFunctionContaining(module.baseAddress, first.startAddress + 0x20) != nullptr &&
           database.FindXRefsTo(module.baseAddress, firstString.address).size() == 1,
           "analysis database indexes functions and Xrefs by address");

    first.name = "first_updated";
    openreverse::FunctionInfo second;
    second.startAddress = module.baseAddress + 0x1100;
    second.name = "second";
    openreverse::StringResult secondString{module.baseAddress + 0x2010, "beta",
        openreverse::StringEncoding::ASCII, 4};
    openreverse::FieldAccessCandidate rcxField;
    rcxField.instructionAddress = first.startAddress + 8;
    rcxField.offset = 0x10;
    rcxField.baseRegister = "rcx";
    openreverse::FieldAccessCandidate rdxField = rcxField;
    rdxField.baseRegister = "rdx";
    const uint64_t mergedRevision = database.MergeModuleAnalysis(
        module, true, pe, {first, second}, {firstXref}, {firstString, secondString}, {},
        {rcxField, rdxField});
    const auto* merged = database.GetModule(module.baseAddress);
    Expect(merged && mergedRevision > initialRevision && merged->functions.size() == 2 &&
           merged->functions[0].name == "first_updated",
           "incremental analysis updates existing functions and advances the revision");
    Expect(merged && merged->xrefs.size() == 1 && merged->strings.size() == 2,
           "incremental analysis deduplicates Xrefs and strings");
    Expect(merged && merged->fieldAccesses.size() == 2,
           "field accesses on different base registers remain distinct");

    database.ReplaceModuleAnalysis(module, true, pe, {second}, {}, {});
    const auto* replaced = database.GetModule(module.baseAddress);
    Expect(replaced && replaced->functions.size() == 1 && replaced->functions[0].name == "second" &&
           replaced->xrefs.empty() && replaced->strings.empty(),
           "complete replacement removes stale module analysis records");
    database.Clear();
    Expect(database.GetModules().empty(), "analysis database clears target-owned records");
}

void TestDataCandidates()
{
    auto raw = BuildMinimalPE64();
    openreverse::PEParser parser;
    const auto pe = parser.ParseBuffer(raw.data(), raw.size());
    openreverse::ModuleInfo module{"fixture.exe", "fixture.exe", pe.imageBase, pe.sizeOfImage};

    openreverse::XRefEntry read;
    read.fromAddress = pe.imageBase + 0x1010;
    read.toAddress = pe.imageBase + 0x2010;
    read.type = openreverse::XRefType::Read;
    openreverse::XRefEntry write = read;
    write.fromAddress += 4;
    write.type = openreverse::XRefType::Write;
    openreverse::XRefEntry codeReference = read;
    codeReference.toAddress = pe.imageBase + 0x1010;

    const auto globals = openreverse::FindGlobalCandidates(module, pe, {read, write, codeReference});
    Expect(globals.size() == 1 && globals[0].address == pe.imageBase + 0x2010 &&
           globals[0].sectionName == ".data" && globals[0].readCount == 1 && globals[0].writeCount == 1,
           "global candidates aggregate typed data Xrefs and reject executable targets");

    const uint8_t fieldCode[] = {
        0x48, 0x8B, 0x41, 0x10,       // mov rax, [rcx+0x10]
        0x89, 0x51, 0x20,             // mov [rcx+0x20], edx
        0x48, 0x8D, 0x41, 0x30,       // lea rax, [rcx+0x30]
        0x48, 0x8B, 0x45, 0xF8        // mov rax, [rbp-8]
    };
    openreverse::Disassembler disassembler;
    Expect(disassembler.Init(true), "field-access test initializes x64 decoder");
    const auto instructions = disassembler.Disassemble(fieldCode, sizeof(fieldCode), pe.imageBase + 0x1000, 16);
    auto fields = openreverse::FindFieldAccesses(instructions);
    Expect(fields.size() == 3, "field candidates retain object-relative operands and reject stack accesses");
    if (fields.size() == 3)
    {
        Expect(fields[0].offset == 0x10 && fields[0].access == openreverse::DataAccessType::Read,
               "field candidate records read offset and access type");
        Expect(fields[1].offset == 0x20 && fields[1].access == openreverse::DataAccessType::Write,
               "field candidate records write offset and access type");
        Expect(fields[2].offset == 0x30 && fields[2].access == openreverse::DataAccessType::Address,
               "field candidate distinguishes address-taking LEA");
    }
    openreverse::FunctionInfo owner;
    owner.startAddress = pe.imageBase + 0x1000;
    owner.endAddress = owner.startAddress + sizeof(fieldCode);
    openreverse::AssignFieldFunctions(fields, {owner});
    const auto structures = openreverse::InferStructures(fields);
    Expect(structures.size() == 1 && structures[0].fields.size() == 3 &&
           structures[0].functionAddress == owner.startAddress && structures[0].estimatedSize >= 0x31,
           "structure inference groups repeated base-register fields by owning function");

    const uint8_t negativeFieldCode[] = {0x8B, 0x41, 0xF8};
    const auto negativeInstructions = disassembler.Disassemble(
        negativeFieldCode, sizeof(negativeFieldCode), pe.imageBase + 0x1080, 4);
    const auto negativeFields = openreverse::FindFieldAccesses(negativeInstructions);
    Expect(negativeFields.size() == 1 && negativeFields[0].displacement == -8 &&
           negativeFields[0].offset == -8,
           "field candidates preserve bounded signed object displacements");

    const uint8_t propagatedCode[] = {
        0x48, 0x8B, 0xD9,             // mov rbx, rcx
        0x8B, 0x43, 0x20,             // mov eax, [rbx+0x20]
        0x89, 0x53, 0x24              // mov [rbx+0x24], edx
    };
    const auto propagatedInstructions = disassembler.Disassemble(
        propagatedCode, sizeof(propagatedCode), pe.imageBase + 0x1100, 16);
    auto propagatedFields = openreverse::FindFieldAccesses(propagatedInstructions);
    Expect(propagatedFields.size() == 2 && propagatedFields[0].argumentIndex == 1 &&
           propagatedFields[0].originRegister == "rcx" &&
           propagatedFields[0].originKind == openreverse::RegisterOriginKind::RegisterCopy,
           "register-copy propagation retains Windows x64 argument origin");
    if (propagatedFields.size() == 2)
    {
        Expect(propagatedFields[0].baseRegister == "rbx" &&
               propagatedFields[0].access == openreverse::DataAccessType::Read,
               "propagated field retains observed base register and READ access");
        Expect(propagatedFields[1].access == openreverse::DataAccessType::Write,
               "propagated field retains WRITE access");
    }
}

void TestSignatures()
{
    const uint64_t base = 0x140001000ULL;
    const uint8_t code[] = {
        0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00,
        0xE8, 0x04, 0x00, 0x00, 0x00,
        0x48, 0x85, 0xC0,
        0xC3
    };
    openreverse::Disassembler disassembler;
    Expect(disassembler.Init(true), "signature test initializes x64 decoder");
    const auto instructions = disassembler.Disassemble(code, sizeof(code), base, 16);
    openreverse::SignatureEngine engine;
    openreverse::SignatureRelationship relationship;
    relationship.kind = openreverse::SignatureTargetKind::RipRelativeOperand;
    relationship.operandIndex = 1;
    openreverse::SignatureGenerationOptions options;
    options.minimumBytes = 12;
    options.maximumBytes = 32;
    options.imageBase = 0x140000000ULL;
    options.imageSize = 0x100000;
    auto signature = engine.Generate(instructions, 0, relationship, options);
    Expect(signature.pattern.size() == 12 && signature.pattern[3].wildcard &&
           signature.pattern[6].wildcard && signature.pattern[8].wildcard &&
           signature.pattern[11].wildcard,
           "signature generation wildcards RIP displacement and relative call target bytes");
    const auto resolved = engine.Resolve(signature, base, instructions);
    Expect(resolved.valid && resolved.address == base + 7 + 0x10,
           "signature relationship resolves a RIP-relative global");

    auto raw = BuildMinimalPE64();
    openreverse::PEParser parser;
    const auto pe = parser.ParseBuffer(raw.data(), raw.size());
    std::vector<uint8_t> mapped;
    Expect(openreverse::PEParser::BuildMappedImage(raw, pe, mapped),
           "signature fixture maps a PE image");
    std::memcpy(mapped.data() + 0x1010, code, sizeof(code));
    signature.stableId = "signature-test";
    engine.Evaluate(signature, mapped, pe, raw.size());
    Expect(signature.status == openreverse::SignatureStatus::Unique && signature.matchCount == 1,
           "signature uniqueness is measured across executable sections");
    std::memcpy(mapped.data() + 0x1050, code, sizeof(code));
    engine.Evaluate(signature, mapped, pe, raw.size());
    Expect(signature.status == openreverse::SignatureStatus::Ambiguous && signature.matchCount == 2,
           "duplicate signature matches are reported as ambiguous");

    const uint8_t fieldCode[] = {
        0x8B, 0x81, 0xA8, 0x01, 0x00, 0x00,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    };
    const auto fieldInstructions = disassembler.Disassemble(fieldCode, sizeof(fieldCode), base, 16);
    relationship.kind = openreverse::SignatureTargetKind::FieldDisplacement;
    relationship.operandIndex = 1;
    auto fieldSignature = engine.Generate(fieldInstructions, 0, relationship, options);
    const auto field = engine.Resolve(fieldSignature, base, fieldInstructions);
    Expect(fieldSignature.pattern.size() == sizeof(fieldCode) && fieldSignature.pattern[2].wildcard &&
           fieldSignature.pattern[5].wildcard && field.valid && field.value == 0x1A8,
           "field signature wildcards and resolves the structure displacement");
}

void TestOffsetProjectsAndIdentity()
{
    openreverse::PEInfo pe;
    pe.valid = true;
    pe.timestamp = 0x12345678;
    pe.sizeOfImage = 0x3000;
    pe.imageBase = 0x140000000ULL;
    const std::vector<uint8_t> bytes{'a', 'b', 'c'};
    openreverse::ModuleIdentity identity;
    std::string error;
    Expect(openreverse::ComputeModuleIdentity(bytes, pe, "fixture.exe", identity, error) &&
           identity.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
           "module identity uses SHA-256 over supplied module bytes");

    openreverse::OffsetProject project;
    project.module = identity;
    openreverse::OffsetRecord first;
    first.stableId = "field:1";
    first.name = "state-value";
    first.kind = openreverse::OffsetKind::StructureField;
    first.fieldOffset = 0x1A8;
    first.module = "fixture.exe";
    first.accessType = openreverse::DataAccessType::Read;
    first.evidence = openreverse::EvidenceLevel::Inferred;
    first.evidenceScore = 3;
    first.provenance = {"Arg1 origin", "decoded operand"};
    project.offsets.push_back(first);
    first.stableId = "field:2";
    first.name = "state value";
    project.offsets.push_back(first);
    first.stableId = "field:3";
    first.name = "negative field";
    first.fieldOffset = -8;
    project.offsets.push_back(first);
    openreverse::SignatureRecord signature;
    signature.stableId = "sig:1";
    signature.pattern = openreverse::PatternScanner::ParsePattern("48 8B ?? FF");
    project.signatures.push_back(signature);

    const std::string json = openreverse::SerializeOffsetProject(project);
    openreverse::OffsetProject imported;
    Expect(openreverse::ParseOffsetProject(json, imported, error) && imported.offsets.size() == 3 &&
           imported.signatures.size() == 1 && imported.module.sha256 == identity.sha256,
           "offset project JSON round-trips typed offsets, signatures, and module identity");
    const std::string header = openreverse::ExportOffsetHeader(imported);
    Expect(header.find("state_value") != std::string::npos &&
           header.find("state_value_2") != std::string::npos &&
           header.find("std::ptrdiff_t negative_field = -0x8") != std::string::npos,
           "C++ header export sanitizes identifiers, handles duplicates, and preserves signed fields");
    Expect(!openreverse::ParseOffsetProject("{invalid", imported, error) && !error.empty(),
           "malformed offset JSON fails with an actionable error");
}

void TestBinaryDiffAndMigration()
{
    const uint64_t oldBase = 0x140010000ULL;
    const uint64_t newBase = 0x180020000ULL;
    const auto oldFunction = AnalyzeCFG({0x85, 0xC9, 0x74, 0x01, 0xC3, 0xC3}, oldBase);
    const auto newFunction = AnalyzeCFG({0x85, 0xC9, 0x74, 0x01, 0xC3, 0xC3}, newBase);
    const auto unrelated = AnalyzeCFG({0x31, 0xC0, 0xC3}, newBase + 0x100);
    const auto oldFingerprint = openreverse::BuildFunctionFingerprint(oldFunction, {"shared-string"});
    const auto newFingerprint = openreverse::BuildFunctionFingerprint(newFunction, {"shared-string"});
    const auto unrelatedFingerprint = openreverse::BuildFunctionFingerprint(unrelated, {"other"});
    std::vector<std::string> evidence;
    const double similar = openreverse::CompareFunctionFingerprints(
        oldFingerprint, newFingerprint, &evidence);
    const double different = openreverse::CompareFunctionFingerprints(
        oldFingerprint, unrelatedFingerprint);
    Expect(similar > different && similar > 0.95 && !evidence.empty(),
           "normalized function fingerprints ignore location while retaining reviewable evidence");

    auto unique = openreverse::CompareFunctionSets({oldFingerprint},
        {newFingerprint, unrelatedFingerprint});
    Expect(unique.size() == 1 && unique[0].status == openreverse::MigrationStatus::UniqueCandidate &&
           unique[0].candidates.front().newAddress == newBase,
           "offset migration produces a unique review candidate for a strong match");
    auto duplicate = newFingerprint;
    duplicate.functionAddress = newBase + 0x200;
    auto ambiguous = openreverse::CompareFunctionSets({oldFingerprint},
        {newFingerprint, duplicate});
    Expect(ambiguous.size() == 1 && ambiguous[0].status == openreverse::MigrationStatus::Ambiguous,
           "equally strong migration matches remain explicitly ambiguous");
}

void TestDumpImportAndDeniedAccess()
{
    char tempPath[MAX_PATH]{};
    GetTempPathA(MAX_PATH, tempPath);
    const std::string mappedPath = std::string(tempPath) + "openreverse-mapped-fixture-" +
        std::to_string(GetCurrentProcessId()) + ".bin";
    const std::string rawPath = std::string(tempPath) + "openreverse-raw-fixture-" +
        std::to_string(GetCurrentProcessId()) + ".bin";

    auto rawPe = BuildMinimalPE64();
    openreverse::PEParser parser;
    const auto pe = parser.ParseBuffer(rawPe.data(), rawPe.size());
    std::vector<uint8_t> mapped;
    openreverse::PEParser::BuildMappedImage(rawPe, pe, mapped);
    {
        std::ofstream file(mappedPath, std::ios::binary);
        file.write(reinterpret_cast<const char*>(mapped.data()), mapped.size());
    }
    const std::vector<uint8_t> snapshot(64, 0x90);
    {
        std::ofstream file(rawPath, std::ios::binary);
        file.write(reinterpret_cast<const char*>(snapshot.data()), snapshot.size());
    }

    openreverse::DumpLoader loader;
    const auto mappedDump = loader.Load(mappedPath);
    Expect(mappedDump.success &&
           mappedDump.representation == openreverse::DumpRepresentation::MappedPEImage &&
           mappedDump.pe.imageBase == pe.imageBase,
           "mapped PE dump is detected and loaded with direct RVA semantics");
    const auto missingMetadata = loader.Load(rawPath);
    Expect(!missingMetadata.success && missingMetadata.error.find("architecture") != std::string::npos,
           "unknown raw dump requires explicit critical metadata");
    openreverse::DumpImportOptions options;
    options.representation = openreverse::DumpRepresentation::RawSnapshot;
    options.architecture = openreverse::DumpArchitecture::X64;
    options.imageBase = 0x180000000ULL;
    options.moduleSize = snapshot.size();
    const auto rawDump = loader.Load(rawPath, options);
    Expect(rawDump.success && rawDump.module.baseAddress == options.imageBase &&
           rawDump.imageBytes.size() == snapshot.size(),
           "raw snapshot import preserves explicit architecture, base, and module size");
    DeleteFileA(mappedPath.c_str());
    DeleteFileA(rawPath.c_str());

    const std::string denied = openreverse::ProcessOpenFailureMessage(ERROR_ACCESS_DENIED);
    Expect(denied.find("denied") != std::string::npos &&
           denied.find("user-provided dump") != std::string::npos &&
           denied.find("bypass") == std::string::npos,
           "denied process access reports safe offline alternatives without bypass guidance");
}

} // namespace

int main()
{
    TestSharedUtilities();
    TestPEMapping();
    TestAddressSpacesAndRuntimeFunctions();
    TestMappedAnalysisPipeline();
    TestMalformedPEs();
    TestBuiltExecutablePE();
    TestLiveExecutableSections();
    TestDecodedFunctionCalls();
    TestRecursiveCFG();
    TestTypedXRefs();
    TestPatternParsing();
    TestOfflinePatternScanning();
    TestAnalysisScheduler();
    TestAnalysisDatabase();
    TestDataCandidates();
    TestSignatures();
    TestOffsetProjectsAndIdentity();
    TestBinaryDiffAndMigration();
    TestDumpImportAndDeniedAccess();

    if (failures != 0)
    {
        std::cerr << failures << " core test(s) failed\n";
        return 1;
    }
    std::cout << "All OpenReverse core tests passed\n";
    return 0;
}
