#include "core/disassembler.h"
#include "core/address_space.h"
#include "core/binary_diff.h"
#include "core/dump_loader.h"
#include "core/offset_model.h"
#include "core/signature_engine.h"
#include "core/analysis_scheduler.h"
#include "core/analysis_database.h"
#include "core/analysis_session.h"
#include "core/data_analyzer.h"
#include "core/dia_symbol_provider.h"
#include "core/function_analyzer.h"
#include "core/instruction_semantics.h"
#include "core/memory_reader.h"
#include "core/module_analyzer.h"
#include "core/pattern_scanner.h"
#include "core/pe_parser.h"
#include "core/process_manager.h"
#include "core/project.h"
#include "core/string_scanner.h"
#include "core/version_intelligence.h"
#include "core/xref_scanner.h"
#include "extensions/extension_manifest.h"
#include "extensions/extension_manager.h"
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
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <map>
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

void TestInstructionSemantics()
{
    const uint8_t code[] = {
        0xE8, 0x00, 0x00, 0x00, 0x00, // call next
        0x75, 0x00,                   // jne next
        0xEB, 0x00,                   // jmp next
        0xC3,                         // ret
        0xCC,                         // int3
        0x90                          // nop
    };
    openreverse::Disassembler disassembler;
    Expect(disassembler.Init(true), "semantic test initializes Capstone");
    const auto decoded = disassembler.Disassemble(code, sizeof(code), 0x140001000ULL, 16);
    Expect(decoded.size() == 6, "semantic fixture decodes every instruction");
    if (decoded.size() != 6) return;

    Expect(decoded[0].isCall && !decoded[0].isJump,
           "Capstone call group classifies a call");
    Expect(decoded[1].isConditionalBranch && decoded[1].isJump &&
           !decoded[1].isUnconditionalBranch,
           "Capstone jump group and ID classify a conditional branch");
    Expect(decoded[2].isUnconditionalBranch && decoded[2].isJump &&
           !decoded[2].isConditionalBranch,
           "Capstone jump group and ID classify an unconditional branch");
    Expect(decoded[3].isRet && !decoded[3].isJump,
           "Capstone return group classifies a return");
    Expect(decoded[4].isInterrupt, "Capstone interrupt group classifies a trap");
    Expect(!decoded[5].isCall && !decoded[5].isJump && !decoded[5].isRet &&
           !decoded[5].isInterrupt,
           "linear instructions remain outside control-flow classes");
}

void TestDiaSymbols()
{
#if OPENREVERSE_HAS_DIA
    const std::filesystem::path executable = OPENREVERSE_TEST_FIXTURE_EXE;
    const std::filesystem::path pdb = OPENREVERSE_TEST_FIXTURE_PDB;
    Expect(openreverse::DiaSymbolProvider::IsAvailable(),
           "DIA provider reports availability when the SDK is configured");
    Expect(std::filesystem::exists(executable) && std::filesystem::exists(pdb),
           "controlled symbol fixture emits an executable and PDB");

    std::vector<uint8_t> raw;
    openreverse::PEParser parser;
    const auto pe = parser.ParseFile(executable.u8string(), raw);
    Expect(pe.valid && !pe.pdbGuid.empty() && pe.pdbAge != 0,
           "PE parser extracts bounded RSDS GUID and age provenance");
    openreverse::ModuleIdentity identity;
    std::string identityError;
    Expect(openreverse::ComputeModuleIdentity(raw, pe, executable.filename().u8string(),
                                              identity, identityError),
           "controlled symbol fixture computes module identity");

    openreverse::DiaSymbolProvider provider;
    const bool loaded = provider.Load(executable.u8string(), identity);
    if (!loaded)
        std::cerr << "DIA fixture error: " << provider.LastError() << '\n';
    Expect(loaded, "DIA validates and loads the executable-associated PDB");
    if (!loaded) return;
    const auto hasNamedFunction = [&](const char* fragment) {
        return std::any_of(provider.Symbols().begin(), provider.Symbols().end(),
            [&](const openreverse::SymbolRecord& symbol) {
                return symbol.kind == openreverse::SymbolKind::Function &&
                       symbol.name.find(fragment) != std::string::npos &&
                       symbol.rva != 0 && symbol.size != 0;
            });
    };
    Expect(hasNamedFunction("VerifyLicenseKey") && hasNamedFunction("SecretPayload"),
           "DIA returns named function RVAs and boundaries from the controlled fixture");
    const auto fixtureType = std::find_if(provider.Types().begin(), provider.Types().end(),
        [](const openreverse::SymbolTypeRecord& type) {
            return type.name.find("FixturePacket") != std::string::npos;
        });
    const auto payloadField = fixtureType == provider.Types().end()
        ? std::vector<openreverse::SymbolFieldRecord>::const_iterator{}
        : std::find_if(fixtureType->fields.begin(), fixtureType->fields.end(),
            [](const openreverse::SymbolFieldRecord& field) {
                return field.name == "payload" && field.offset == 8 && field.size == 8;
            });
    Expect(fixtureType != provider.Types().end() && payloadField != fixtureType->fields.end(),
           "DIA returns structure names, field offsets, and field widths");
    const auto fixtureEnum = std::find_if(provider.Types().begin(), provider.Types().end(),
        [](const openreverse::SymbolTypeRecord& type) {
            return type.kind == openreverse::SymbolTypeKind::Enum &&
                   type.name.find("FixtureMode") != std::string::npos;
        });
    Expect(fixtureEnum != provider.Types().end() &&
           std::find(fixtureEnum->enumValues.begin(), fixtureEnum->enumValues.end(),
                     std::make_pair(std::string("Omega"), int64_t{7})) !=
               fixtureEnum->enumValues.end(),
           "DIA returns bounded enum names and values");
    Expect(provider.Identity().executableAssociationValidated &&
           openreverse::helpers::ToLower(provider.Identity().guid) ==
               openreverse::helpers::ToLower(identity.pdbGuid) &&
           provider.Identity().age == identity.pdbAge,
           "DIA identity matches the PE CodeView GUID and age");

    auto mismatchedIdentity = identity;
    ++mismatchedIdentity.pdbAge;
    openreverse::DiaSymbolProvider mismatchedProvider;
    Expect(!mismatchedProvider.Load(executable.u8string(), mismatchedIdentity) &&
           mismatchedProvider.LastError().find("age") != std::string::npos,
           "DIA rejects a PDB whose age does not match the PE identity");

    std::vector<uint8_t> mapped;
    Expect(openreverse::PEParser::BuildMappedImage(raw, pe, mapped),
           "controlled symbol fixture builds a mapped image");
    openreverse::ModuleInfo module{
        executable.filename().u8string(), executable.u8string(), pe.imageBase, pe.sizeOfImage};
    openreverse::ModuleAnalysisOptions options;
    options.maxInstructions = 200000;
    options.maxCfgInstructions = 100000;
    options.maxFunctions = 20000;
    const auto analysis = openreverse::ModuleAnalyzer{}.AnalyzeMappedImage(
        mapped, raw.size(), module, pe, options);
    const auto symbolFunction = std::find_if(analysis.functions.begin(), analysis.functions.end(),
        [](const openreverse::FunctionInfo& function) {
            return function.name.find("VerifyLicenseKey") != std::string::npos;
        });
    Expect(analysis.success && analysis.symbolsLoaded && symbolFunction != analysis.functions.end(),
           "mapped analysis publishes DIA symbols through its canonical result");
    Expect(symbolFunction != analysis.functions.end() && symbolFunction->boundaryKnown &&
           std::find(symbolFunction->provenance.begin(), symbolFunction->provenance.end(),
                     openreverse::FunctionSource::Symbol) != symbolFunction->provenance.end(),
           "symbol-derived function boundaries retain explicit provenance after CFG analysis");
#else
    Expect(!openreverse::DiaSymbolProvider::IsAvailable(),
           "DIA provider remains explicitly optional without the SDK");
#endif
}

class TemporaryDirectory {
public:
    explicit TemporaryDirectory(const char* label)
    {
        path_ = std::filesystem::temp_directory_path() /
            (std::string("openreverse-") + label + "-" +
             std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
        std::filesystem::create_directories(path_);
    }

    ~TemporaryDirectory()
    {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& Path() const { return path_; }

private:
    std::filesystem::path path_;
};

void WriteTextFile(const std::filesystem::path& path, const std::string& text)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!stream) throw std::runtime_error("test fixture file write failed");
}

std::string ExtensionManifestText(const std::string& id, const std::string& entrypoint,
                                  uint32_t apiVersion = 1,
                                  const std::string& minimumVersion = "2.0.0",
                                  const std::string& capabilities =
                                      "\"analysis.read\",\"navigation\",\"ui.panel\",\"ui.command\"")
{
    return "{\"id\":\"" + id + "\",\"name\":\"Fixture\",\"version\":\"0.1.0\"," +
        "\"api_version\":" + std::to_string(apiVersion) +
        ",\"minimum_openreverse_version\":\"" + minimumVersion +
        "\",\"author\":\"Tests\",\"description\":\"Compatibility fixture\"," +
        "\"entrypoint\":\"" + entrypoint + "\",\"capabilities\":[" + capabilities + "]}";
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
    Expect(runtimeFunction != analysis.functions.end() &&
           !runtimeFunction->cfg.basicBlocks.empty() &&
           runtimeFunction->cfg.decodedInstructionCount != 0 &&
           analysis.cfgFunctionsAnalyzed != 0,
           "mapped analysis publishes canonical per-function CFG evidence");
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

void TestBoundedParserMutationCorpus()
{
    openreverse::PEParser parser;
    const auto validPE = BuildMinimalPE64();
    bool peThrew = false;
    try
    {
        (void)parser.ParseBuffer(nullptr, 0);
        for (size_t size = 1; size < validPE.size(); ++size)
            (void)parser.ParseBuffer(validPE.data(), size);

        uint32_t state = 0x4F524556U;
        for (size_t iteration = 0; iteration < 512; ++iteration)
        {
            auto mutated = validPE;
            const size_t changes = 1 + iteration % 4;
            for (size_t change = 0; change < changes; ++change)
            {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                const size_t offset = state % mutated.size();
                mutated[offset] ^= static_cast<uint8_t>(state >> 24);
            }
            const auto info = parser.ParseBuffer(mutated.data(), mutated.size());
            if (info.valid)
            {
                std::vector<uint8_t> mapped;
                Expect(openreverse::PEParser::BuildMappedImage(mutated, info, mapped) &&
                       mapped.size() <= 256ULL * 1024ULL * 1024ULL,
                       "valid mutated PEs map within the global image budget");
            }
        }
    }
    catch (...)
    {
        peThrew = true;
    }
    Expect(!peThrew, "truncated and deterministically mutated PE inputs never escape exceptions");

    bool projectThrew = false;
    try
    {
        uint32_t state = 0x50524F4AU;
        for (size_t iteration = 0; iteration < 256; ++iteration)
        {
            const size_t length = iteration * 4;
            std::string input(length, '\0');
            for (char& character : input)
            {
                state = state * 1664525U + 1013904223U;
                character = static_cast<char>(state >> 24);
            }
            openreverse::OpenReverseProject project;
            std::string error;
            (void)openreverse::ProjectStore::Parse(input, project, error);
        }
    }
    catch (...)
    {
        projectThrew = true;
    }
    Expect(!projectThrew, "bounded malformed project inputs never escape exceptions");

    TemporaryDirectory manifests("manifest-mutations");
    const auto manifestPath = manifests.Path() / "manifest.json";
    bool manifestThrew = false;
    try
    {
        uint32_t state = 0x4D414E49U;
        for (size_t iteration = 0; iteration < 128; ++iteration)
        {
            std::string input(iteration * 8 + 1, '\0');
            for (char& character : input)
            {
                state = state * 1103515245U + 12345U;
                character = static_cast<char>((state >> 16) & 0x7F);
            }
            WriteTextFile(manifestPath, input);
            openreverse::extensions::ExtensionManifest manifest;
            std::string error;
            (void)openreverse::extensions::ParseExtensionManifest(manifestPath, manifest, error);
        }
    }
    catch (...)
    {
        manifestThrew = true;
    }
    Expect(!manifestThrew, "bounded malformed extension manifests never escape exceptions");
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

    const uint64_t flowBase = pe.imageBase + 0x1200;
    auto interBlockFunction = AnalyzeCFG({
        0x48, 0x8B, 0xD9,             // mov rbx, rcx
        0xEB, 0x00,                   // jmp next block
        0x8B, 0x43, 0x18,             // mov eax, [rbx+0x18]
        0xC3
    }, flowBase);
    const auto interBlockFields = openreverse::FindFieldAccesses(interBlockFunction);
    const auto interBlockField = std::find_if(interBlockFields.begin(), interBlockFields.end(),
        [](const openreverse::FieldAccessCandidate& field) { return field.offset == 0x18; });
    Expect(interBlockField != interBlockFields.end() && interBlockField->argumentIndex == 1 &&
           interBlockField->originRegister == "rcx" && interBlockField->interBlock &&
           !interBlockField->mergeAmbiguous,
           "argument origin propagates across a simple CFG predecessor");

    auto conflictingFunction = AnalyzeCFG({
        0x85, 0xC0,                   // test eax, eax
        0x74, 0x05,                   // je alternate
        0x48, 0x8B, 0xD9,             // mov rbx, rcx
        0xEB, 0x03,                   // jmp join
        0x48, 0x8B, 0xDA,             // mov rbx, rdx
        0x8B, 0x43, 0x18,             // join: mov eax, [rbx+0x18]
        0xC3
    }, flowBase + 0x100);
    const auto conflictingFields = openreverse::FindFieldAccesses(conflictingFunction);
    const auto conflictingField = std::find_if(conflictingFields.begin(), conflictingFields.end(),
        [](const openreverse::FieldAccessCandidate& field) { return field.offset == 0x18; });
    Expect(conflictingField != conflictingFields.end() && conflictingField->mergeAmbiguous &&
           conflictingField->originKind == openreverse::RegisterOriginKind::Ambiguous &&
           conflictingField->argumentIndex == 0 && conflictingField->predecessorCount == 2,
           "conflicting predecessor origins remain explicit and do not select an argument");

    auto callReturnFunction = AnalyzeCFG({
        0xE8, 0x00, 0x00, 0x00, 0x00, // direct call
        0x48, 0x8B, 0xD8,             // mov rbx, rax
        0x8B, 0x43, 0x10,             // mov eax, [rbx+0x10]
        0xC3
    }, flowBase + 0x200);
    const auto callReturnFields = openreverse::FindFieldAccesses(callReturnFunction);
    const auto callReturnField = std::find_if(callReturnFields.begin(), callReturnFields.end(),
        [](const openreverse::FieldAccessCandidate& field) { return field.offset == 0x10; });
    Expect(callReturnField != callReturnFields.end() &&
           callReturnField->originKind == openreverse::RegisterOriginKind::CallReturn &&
           callReturnField->callInstructionAddress == flowBase + 0x200 &&
           callReturnField->callTargetAddress == flowBase + 0x205,
           "direct-call return provenance survives a straightforward register copy");
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

    const auto ordered = AnalyzeCFG({
        0x48, 0x89, 0xC8, 0x48, 0x01, 0xD0, 0x4C, 0x31, 0xC0, 0xC3},
        oldBase + 0x400);
    const auto reordered = AnalyzeCFG({
        0x48, 0x89, 0xC8, 0x4C, 0x31, 0xC0, 0x48, 0x01, 0xD0, 0xC3},
        newBase + 0x400);
    const auto orderSimilarity = openreverse::EvaluateFunctionFingerprints(
        openreverse::BuildFunctionFingerprint(ordered),
        openreverse::BuildFunctionFingerprint(reordered));
    Expect(orderSimilarity.normalizedInstructions == 1.0 &&
           orderSimilarity.orderedInstructions < orderSimilarity.normalizedInstructions &&
           !orderSimilarity.exactNormalized && orderSimilarity.total < 0.90,
           "the same instruction multiset in a different order cannot claim an exact match");
}

openreverse::FunctionInfo NamedFunction(std::initializer_list<uint8_t> code, uint64_t address,
                                        const char* name)
{
    auto function = AnalyzeCFG(std::vector<uint8_t>(code), address);
    function.name = name;
    function.boundaryKnown = true;
    function.size = function.analyzedSize;
    return function;
}

void TestVersionIntelligence()
{
    const uint64_t oldBase = 0x140000000ULL;
    const uint64_t newBase = 0x180000000ULL;
    openreverse::VersionAnalysisTarget oldTarget;
    openreverse::VersionAnalysisTarget newTarget;
    oldTarget.identity = {"build-a.exe", "", std::string(64, 'a'), "x64", 1, 0x3000, oldBase};
    newTarget.identity = {"build-b.exe", "", std::string(64, 'b'), "x64", 2, 0x3000, newBase};
    oldTarget.analysis.module = {"build-a.exe", "", oldBase, 0x3000};
    newTarget.analysis.module = {"build-b.exe", "", newBase, 0x3000};
    oldTarget.analysis.is64Bit = true;
    newTarget.analysis.is64Bit = true;

    auto movedOld = NamedFunction({0x85, 0xC9, 0x74, 0x01, 0xC3, 0xC3}, oldBase + 0x1000, "moved");
    auto movedNew = NamedFunction({0x85, 0xC9, 0x74, 0x01, 0xC3, 0xC3}, newBase + 0x1100, "moved_v2");
    auto changedOld = NamedFunction({0x48, 0x83, 0xC0, 0x01, 0xC3}, oldBase + 0x1200, "changed");
    auto changedNew = NamedFunction({0x48, 0x83, 0xC0, 0x01, 0x90, 0xC3}, newBase + 0x1250, "changed_v2");
    auto cfgOld = NamedFunction({0x85, 0xC9, 0x74, 0x02, 0x31, 0xC0, 0xC3}, oldBase + 0x1300, "cfg_old");
    auto cfgNew = NamedFunction({0x85, 0xC9, 0x75, 0x02, 0x31, 0xC0, 0xC3}, newBase + 0x1350, "cfg_new");
    auto stringOld = NamedFunction({0x48, 0x31, 0xC0, 0xC3}, oldBase + 0x1400, "shared_string_old");
    auto stringUnrelated = NamedFunction({0x48, 0xFF, 0xC1, 0xC3}, newBase + 0x1450, "shared_string_unrelated");
    auto ambiguousOld = NamedFunction({0x31, 0xC0, 0xC3}, oldBase + 0x1500, "ambiguous");
    auto ambiguousA = NamedFunction({0x31, 0xC0, 0xC3}, newBase + 0x1550, "ambiguous_a");
    auto ambiguousB = NamedFunction({0x31, 0xC0, 0xC3}, newBase + 0x1580, "ambiguous_b");
    auto removed = NamedFunction({0x0F, 0x31, 0x48, 0x31, 0xD2, 0xC3}, oldBase + 0x1600, "removed");
    auto added = NamedFunction({0x48, 0xF7, 0xD1, 0xC3}, newBase + 0x1650, "new_function");
    auto calleeOld = NamedFunction({0x83, 0xC0, 0x07, 0x90, 0x90, 0xC3}, oldBase + 0x1700, "callee");
    auto calleeNew = NamedFunction({0x83, 0xC0, 0x07, 0x90, 0x90, 0xC3}, newBase + 0x1750, "callee_v2");
    auto parentOld = NamedFunction({0x48, 0x89, 0xC8, 0x83, 0xC0, 0x03, 0xC3}, oldBase + 0x1800, "parent");
    auto parentNew = NamedFunction({0x48, 0x89, 0xC8, 0x83, 0xC0, 0x04, 0xC3}, newBase + 0x1850, "parent_v2");
    parentOld.callTargets = {calleeOld.startAddress};
    parentNew.callTargets = {calleeNew.startAddress};
    auto sameSizeUnrelated = NamedFunction({0x48, 0x29, 0xD8, 0xC3}, newBase + 0x1900, "same_size_unrelated");

    oldTarget.analysis.functions = {movedOld, changedOld, cfgOld, stringOld, ambiguousOld,
                                    removed, calleeOld, parentOld};
    newTarget.analysis.functions = {movedNew, changedNew, cfgNew, stringUnrelated, ambiguousA,
                                    ambiguousB, added, calleeNew, parentNew, sameSizeUnrelated};

    oldTarget.analysis.strings.push_back({oldBase + 0x2200, "shared-text", openreverse::StringEncoding::ASCII, 11});
    newTarget.analysis.strings.push_back({newBase + 0x2210, "shared-text", openreverse::StringEncoding::ASCII, 11});
    oldTarget.analysis.xrefs.push_back({stringOld.startAddress, oldBase + 0x2200,
        openreverse::XRefType::String, 0, 8, stringOld.startAddress, "lea", "build-a.exe"});
    newTarget.analysis.xrefs.push_back({stringUnrelated.startAddress, newBase + 0x2210,
        openreverse::XRefType::String, 0, 8, stringUnrelated.startAddress, "lea", "build-b.exe"});

    openreverse::GlobalCandidate oldGlobal;
    oldGlobal.address = oldBase + 0x2050;
    oldGlobal.rva = 0x2050;
    oldGlobal.sectionName = ".data";
    oldGlobal.kind = openreverse::GlobalKind::WritableData;
    oldGlobal.readCount = 1;
    oldGlobal.sourceFunctions = {movedOld.startAddress};
    oldGlobal.accessSites = {movedOld.startAddress};
    openreverse::GlobalCandidate newGlobal = oldGlobal;
    newGlobal.address = newBase + 0x2070;
    newGlobal.rva = 0x2070;
    newGlobal.sourceFunctions = {movedNew.startAddress};
    newGlobal.accessSites = {movedNew.startAddress};
    oldTarget.analysis.globals.push_back(oldGlobal);
    newTarget.analysis.globals.push_back(newGlobal);

    openreverse::FieldAccessCandidate oldField;
    oldField.instructionAddress = movedOld.startAddress;
    oldField.functionAddress = movedOld.startAddress;
    oldField.displacement = 0x1A8;
    oldField.offset = 0x1A8;
    oldField.operandSize = 4;
    oldField.access = openreverse::DataAccessType::Read;
    oldField.originKind = openreverse::RegisterOriginKind::Argument;
    oldField.originRegister = "rcx";
    oldField.argumentIndex = 1;
    auto newField = oldField;
    newField.instructionAddress = movedNew.startAddress;
    newField.functionAddress = movedNew.startAddress;
    newField.displacement = 0x1B0;
    newField.offset = 0x1B0;
    oldTarget.analysis.fieldAccesses.push_back(oldField);
    newTarget.analysis.fieldAccesses.push_back(newField);

    openreverse::OffsetRecord functionOffset;
    functionOffset.stableId = "function:1000";
    functionOffset.kind = openreverse::OffsetKind::FunctionRva;
    functionOffset.rva = 0x1000;
    functionOffset.sourceFunction = movedOld.startAddress;
    openreverse::OffsetRecord globalOffset;
    globalOffset.stableId = "global:2050";
    globalOffset.kind = openreverse::OffsetKind::GlobalRva;
    globalOffset.rva = 0x2050;
    openreverse::OffsetRecord fieldOffset;
    fieldOffset.stableId = "field:1000:1:424";
    fieldOffset.kind = openreverse::OffsetKind::StructureField;
    fieldOffset.sourceFunction = movedOld.startAddress;
    fieldOffset.fieldOffset = 0x1A8;
    oldTarget.analysis.offsets = {functionOffset, globalOffset, fieldOffset};

    auto raw = BuildMinimalPE64();
    openreverse::PEParser parser;
    oldTarget.analysis.pe = parser.ParseBuffer(raw.data(), raw.size());
    newTarget.analysis.pe = oldTarget.analysis.pe;
    oldTarget.analysis.pe.imageBase = oldBase;
    newTarget.analysis.pe.imageBase = newBase;
    openreverse::PEParser::BuildMappedImage(raw, oldTarget.analysis.pe, oldTarget.mappedImage);
    openreverse::PEParser::BuildMappedImage(raw, newTarget.analysis.pe, newTarget.mappedImage);
    oldTarget.rawFileSize = raw.size();
    newTarget.rawFileSize = raw.size();

    const std::vector<uint8_t> uniquePattern{0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87,0x98,0xA9,0xBA,0xCB};
    const std::vector<uint8_t> duplicatePattern{0xDE,0xAD,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA};
    std::copy(uniquePattern.begin(), uniquePattern.end(), newTarget.mappedImage.begin() + 0x11A0);
    std::copy(duplicatePattern.begin(), duplicatePattern.end(), newTarget.mappedImage.begin() + 0x11C0);
    std::copy(duplicatePattern.begin(), duplicatePattern.end(), newTarget.mappedImage.begin() + 0x11E0);

    const std::vector<uint8_t> oldFieldCode{
        0x8B, 0x81, 0xA8, 0x01, 0x00, 0x00, 0x66, 0x90, 0x40, 0x90, 0x90, 0xC3
    };
    const std::vector<uint8_t> newFieldCode{
        0x8B, 0x81, 0xB0, 0x01, 0x00, 0x00, 0x66, 0x90, 0x40, 0x90, 0x90, 0xC3
    };
    std::copy(oldFieldCode.begin(), oldFieldCode.end(), oldTarget.mappedImage.begin() + 0x1040);
    std::copy(newFieldCode.begin(), newFieldCode.end(), newTarget.mappedImage.begin() + 0x1060);

    std::vector<uint8_t> oldRipCode{
        0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x75, 0x01, 0xC3
    };
    std::vector<uint8_t> newRipCode = oldRipCode;
    const int32_t oldRipDisplacement = static_cast<int32_t>(0x2050 - (0x1080 + 7));
    const int32_t newRipDisplacement = static_cast<int32_t>(0x2070 - (0x10A0 + 7));
    std::memcpy(oldRipCode.data() + 3, &oldRipDisplacement, sizeof(oldRipDisplacement));
    std::memcpy(newRipCode.data() + 3, &newRipDisplacement, sizeof(newRipDisplacement));
    std::copy(oldRipCode.begin(), oldRipCode.end(), oldTarget.mappedImage.begin() + 0x1080);
    std::copy(newRipCode.begin(), newRipCode.end(), newTarget.mappedImage.begin() + 0x10A0);

    openreverse::SignatureRecord uniqueSignature;
    uniqueSignature.stableId = "stable";
    uniqueSignature.pattern.reserve(uniquePattern.size());
    for (uint8_t byte : uniquePattern) uniqueSignature.pattern.push_back({byte, false});
    uniqueSignature.relationship.kind = openreverse::SignatureTargetKind::FunctionRva;
    uniqueSignature.targetFunction = movedOld.startAddress;
    uniqueSignature.targetOffset = 0x1000;
    openreverse::SignatureRecord brokenSignature = uniqueSignature;
    brokenSignature.stableId = "broken";
    brokenSignature.pattern[0].value = 0xFE;
    openreverse::SignatureRecord duplicateSignature = uniqueSignature;
    duplicateSignature.stableId = "duplicate";
    duplicateSignature.pattern.clear();
    for (uint8_t byte : duplicatePattern) duplicateSignature.pattern.push_back({byte, false});
    openreverse::SignatureRecord sharedScanSignature = uniqueSignature;
    sharedScanSignature.stableId = "stable-shared-scan";

    openreverse::Disassembler signatureDisassembler;
    Expect(signatureDisassembler.Init(true), "version signature fixture initializes x64 decoder");
    openreverse::SignatureEngine signatureEngine;
    openreverse::SignatureGenerationOptions signatureOptions;
    signatureOptions.minimumBytes = 12;
    signatureOptions.maximumBytes = 16;
    signatureOptions.imageBase = oldBase;
    signatureOptions.imageSize = oldTarget.analysis.module.size;
    openreverse::SignatureRelationship fieldRelationship;
    fieldRelationship.kind = openreverse::SignatureTargetKind::FieldDisplacement;
    fieldRelationship.operandIndex = 1;
    const auto fieldInstructions = signatureDisassembler.Disassemble(
        oldTarget.mappedImage.data() + 0x1040, oldFieldCode.size(), oldBase + 0x1040, 16);
    auto fieldSignature = signatureEngine.Generate(fieldInstructions, 0, fieldRelationship, signatureOptions);
    fieldSignature.stableId = "field-relation";

    openreverse::SignatureRelationship ripRelationship;
    ripRelationship.kind = openreverse::SignatureTargetKind::RipRelativeOperand;
    ripRelationship.operandIndex = 1;
    const auto ripInstructions = signatureDisassembler.Disassemble(
        oldTarget.mappedImage.data() + 0x1080, oldRipCode.size(), oldBase + 0x1080, 16);
    auto ripSignature = signatureEngine.Generate(ripInstructions, 0, ripRelationship, signatureOptions);
    ripSignature.stableId = "rip-relation";

    oldTarget.analysis.signatures = {uniqueSignature, sharedScanSignature, brokenSignature, duplicateSignature,
                                     fieldSignature, ripSignature};
    auto newSignature = uniqueSignature;
    newSignature.targetFunction = movedNew.startAddress;
    newSignature.targetOffset = 0x1100;
    newTarget.analysis.signatures.push_back(newSignature);

    openreverse::VersionIntelligenceEngine engine;
    const auto comparison = engine.Compare(oldTarget, newTarget);
    Expect(comparison.error.empty() && !comparison.cancelled &&
           comparison.scoredCandidatePairs < oldTarget.analysis.functions.size() * newTarget.analysis.functions.size(),
           "version comparison uses indexed candidates instead of an all-pairs scan");
    Expect(comparison.signatureScansPerformed == 7,
           "identical signature patterns reuse one bounded scan per target");
    const auto findFunction = [&](uint64_t oldRva) -> const openreverse::VersionFunctionMatch* {
        const auto found = std::find_if(comparison.functions.begin(), comparison.functions.end(),
            [&](const openreverse::VersionFunctionMatch& match) { return match.oldRva == oldRva; });
        return found == comparison.functions.end() ? nullptr : &*found;
    };
    const auto* movedMatch = findFunction(0x1000);
    const auto* changedMatch = findFunction(0x1200);
    const auto* ambiguousMatch = findFunction(0x1500);
    const auto* removedMatch = findFunction(0x1600);
    const auto* stringFalseMatch = findFunction(0x1400);
    const auto* parentMatch = findFunction(0x1800);
    Expect(movedMatch && movedMatch->suggestedState == openreverse::VersionMatchState::Exact &&
           movedMatch->candidates.front().newRva == 0x1100,
           "an identical function moved to a new RVA is an exact normalized match");
    Expect(changedMatch && !changedMatch->candidates.empty() &&
           changedMatch->candidates.front().changes.instructionDelta == 1,
           "a changed function remains reviewable with deterministic instruction deltas");
    Expect(ambiguousMatch && ambiguousMatch->suggestedState == openreverse::VersionMatchState::Ambiguous,
           "two equally plausible candidates remain ambiguous");
    Expect(removedMatch && removedMatch->suggestedState == openreverse::VersionMatchState::Removed,
           "a removed function is represented explicitly");
    Expect(std::find(comparison.newFunctionRvas.begin(), comparison.newFunctionRvas.end(), 0x1650) !=
           comparison.newFunctionRvas.end(), "a new function is represented explicitly");
    Expect(std::find(comparison.newFunctionRvas.begin(), comparison.newFunctionRvas.end(), 0x1900) !=
           comparison.newFunctionRvas.end(), "an unrelated same-size function is not force-matched");
    Expect(!stringFalseMatch || stringFalseMatch->suggestedState != openreverse::VersionMatchState::StrongCandidate,
           "a shared common string cannot create an aggressive unrelated match");
    Expect(parentMatch && !parentMatch->candidates.empty() &&
           std::any_of(parentMatch->candidates.front().evidence.begin(),
               parentMatch->candidates.front().evidence.end(), [](const openreverse::VersionEvidence& evidence) {
                   return evidence.kind == openreverse::VersionEvidenceKind::MatchedCallees && evidence.score == 1.0;
               }), "a previously strong callee mapping contributes explicit parent evidence");
    const auto exactCount = std::count_if(comparison.functions.begin(), comparison.functions.end(),
        [](const openreverse::VersionFunctionMatch& match) {
            return match.suggestedState == openreverse::VersionMatchState::Exact;
        });
    const auto ambiguousCount = std::count_if(comparison.functions.begin(), comparison.functions.end(),
        [](const openreverse::VersionFunctionMatch& match) {
            return match.suggestedState == openreverse::VersionMatchState::Ambiguous;
        });
    const auto removedCount = std::count_if(comparison.functions.begin(), comparison.functions.end(),
        [](const openreverse::VersionFunctionMatch& match) {
            return match.suggestedState == openreverse::VersionMatchState::Removed;
        });
    Expect(exactCount >= 2 && ambiguousCount >= 1 && removedCount >= 1 &&
           comparison.newFunctionRvas.size() >= 2,
           "comparison quality counts expose exact, ambiguous, removed, and new outcomes");

    const auto findMigration = [&](const std::string& stableId) -> const openreverse::VersionMigrationCandidate* {
        const auto found = std::find_if(comparison.migrations.begin(), comparison.migrations.end(),
            [&](const openreverse::VersionMigrationCandidate& migration) { return migration.stableId == stableId; });
        return found == comparison.migrations.end() ? nullptr : &*found;
    };
    const auto* globalMigration = findMigration("global:0x2050");
    const auto* stableSignature = findMigration("signature:stable");
    const auto* broken = findMigration("signature:broken");
    const auto* duplicate = findMigration("signature:duplicate");
    const auto* fieldSignatureMigration = findMigration("signature:field-relation");
    const auto* ripSignatureMigration = findMigration("signature:rip-relation");
    Expect(globalMigration && globalMigration->newRva == 0x2070 &&
           globalMigration->suggestedState == openreverse::VersionMatchState::StrongCandidate,
           "global migration follows matched-function access relationships");
    Expect(stableSignature && stableSignature->newRva == 0x11A0 &&
           stableSignature->suggestedState == openreverse::VersionMatchState::StrongCandidate,
           "a unique stable signature produces a reviewable migration");
    Expect(broken && broken->suggestedState == openreverse::VersionMatchState::Unmatched,
           "a broken signature remains unmatched");
    Expect(duplicate && duplicate->suggestedState == openreverse::VersionMatchState::Ambiguous,
           "multiple signature matches remain ambiguous");
    Expect(fieldSignatureMigration && fieldSignatureMigration->oldValue == 0x1A8 &&
           fieldSignatureMigration->newValue == 0x1B0 &&
           fieldSignatureMigration->suggestedState == openreverse::VersionMatchState::StrongCandidate,
           "a relationship-aware signature resolves old and new structure displacements");
    Expect(ripSignatureMigration && ripSignatureMigration->oldRva == 0x2050 &&
           ripSignatureMigration->newRva == 0x2070 &&
           ripSignatureMigration->suggestedState == openreverse::VersionMatchState::StrongCandidate,
           "a relationship-aware signature resolves old and new RIP-relative targets");
    const auto fieldMigration = std::find_if(comparison.migrations.begin(), comparison.migrations.end(),
        [](const openreverse::VersionMigrationCandidate& migration) {
            return migration.kind == openreverse::VersionMigrationKind::StructureField;
        });
    Expect(fieldMigration != comparison.migrations.end() && fieldMigration->oldValue == 0x1A8 &&
           fieldMigration->newValue == 0x1B0 &&
           fieldMigration->suggestedState == openreverse::VersionMatchState::StrongCandidate,
           "structure fields migrate only with matched function, provenance, width, access, and instruction role");
    const auto* functionOffsetMigration = findMigration("offset:function:1000");
    const auto* globalOffsetMigration = findMigration("offset:global:2050");
    Expect(functionOffsetMigration && functionOffsetMigration->newRva == 0x1100 &&
           globalOffsetMigration && globalOffsetMigration->newRva == 0x2070,
           "typed function and global offsets follow their corresponding migration evidence");

    openreverse::CancellationSource cancellation;
    cancellation.Cancel();
    const auto token = cancellation.Token();
    const auto cancelled = engine.Compare(oldTarget, newTarget, &token);
    Expect(cancelled.cancelled, "version comparison honors cancellation");
}

void TestVersionIntelligenceScaling()
{
    constexpr size_t functionCount = 1500;
    const uint64_t oldBase = 0x140000000ULL;
    const uint64_t newBase = 0x180000000ULL;
    openreverse::VersionAnalysisTarget oldTarget;
    openreverse::VersionAnalysisTarget newTarget;
    oldTarget.identity = {"scale-old.exe", "", std::string(64, '3'), "x64", 1,
                          0x800000, oldBase};
    newTarget.identity = {"scale-new.exe", "", std::string(64, '4'), "x64", 2,
                          0x800000, newBase};
    oldTarget.analysis.module = {"scale-old.exe", "", oldBase, 0x800000};
    newTarget.analysis.module = {"scale-new.exe", "", newBase, 0x800000};
    oldTarget.analysis.is64Bit = true;
    newTarget.analysis.is64Bit = true;

    const auto appendFunction = [](openreverse::VersionAnalysisTarget& target,
                                   uint64_t address, uint64_t stringAddress,
                                   uint32_t instructionId, size_t index) {
        openreverse::Instruction instruction;
        instruction.address = address;
        instruction.size = 1;
        instruction.instructionId = instructionId;
        instruction.mnemonic = "fixture";
        openreverse::BasicBlock block;
        block.startAddress = address;
        block.endAddress = address + 1;
        block.instructions.push_back(instruction);
        block.isTerminal = true;
        openreverse::FunctionInfo function;
        function.startAddress = address;
        function.endAddress = address + 1;
        function.name = "scale_" + std::to_string(index);
        function.size = 1;
        function.analyzedSize = 1;
        function.boundaryKnown = true;
        function.cfg.entryAddress = address;
        function.cfg.basicBlocks.push_back(std::move(block));
        function.cfg.decodedInstructionCount = 1;
        target.analysis.functions.push_back(std::move(function));
        target.analysis.strings.push_back({stringAddress, "unique-" + std::to_string(index),
            openreverse::StringEncoding::ASCII, 8});
        openreverse::XRefEntry xref;
        xref.fromAddress = address;
        xref.toAddress = stringAddress;
        xref.type = openreverse::XRefType::String;
        xref.functionAddress = address;
        target.analysis.xrefs.push_back(std::move(xref));
    };
    for (size_t index = 0; index < functionCount; ++index)
    {
        appendFunction(oldTarget, oldBase + 0x1000 + index * 4,
                       oldBase + 0x400000 + index * 16,
                       static_cast<uint32_t>(0x10000 + index), index);
        appendFunction(newTarget, newBase + 0x2000 + index * 4,
                       newBase + 0x500000 + index * 16,
                       static_cast<uint32_t>(0x10000 + index), index);
    }

    const auto started = std::chrono::steady_clock::now();
    const auto comparison = openreverse::VersionIntelligenceEngine{}.Compare(oldTarget, newTarget);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    Expect(comparison.error.empty() && !comparison.candidateBudgetReached &&
           comparison.scoredCandidatePairs == functionCount &&
           comparison.indexedCandidatePairs == functionCount,
           "indexed Version Intelligence scales linearly for unique synthetic functions");
    Expect(elapsed < std::chrono::seconds(5),
           "synthetic Version Intelligence indexing remains within its regression budget");
}

void TestProjectPersistence()
{
    char tempDirectory[MAX_PATH]{};
    GetTempPathA(MAX_PATH, tempDirectory);
    const std::string suffix = std::to_string(GetCurrentProcessId());
    const std::string targetPath = std::string(tempDirectory) + "openreverse-project-target-" + suffix + ".bin";
    const std::string projectPath = std::string(tempDirectory) + "openreverse-project-" + suffix + ".orev";
    DeleteFileA(targetPath.c_str());
    DeleteFileA(projectPath.c_str());

    const auto targetBytes = BuildMinimalPE64();
    {
        std::ofstream file(targetPath, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char*>(targetBytes.data()),
                   static_cast<std::streamsize>(targetBytes.size()));
    }

    openreverse::OpenReverseProject project;
    project.target.kind = openreverse::ProjectTargetKind::PEFile;
    project.target.path = targetPath;
    project.target.architecture = "x64";
    project.target.imageBase = 0x140000000ULL;
    project.target.moduleSize = 0x3000;
    std::string error;
    Expect(openreverse::ProjectStore::ComputeFileSha256(targetPath, project.target.sha256, error),
           "project target identity hashes the original file");
    project.target.module.name = "fixture.exe";
    project.target.module.sha256 = project.target.sha256;
    project.target.module.peTimestamp = 0x12345678;
    project.target.module.imageSize = 0x3000;
    project.target.module.imageBase = project.target.imageBase;

    openreverse::OffsetRecord offset;
    offset.stableId = "user:123";
    offset.name = "g_state";
    offset.kind = openreverse::OffsetKind::UserDefined;
    offset.address = project.target.imageBase + 0x123;
    offset.rva = 0x123;
    offset.sourceFunction = project.target.imageBase + 0x200;
    offset.sourceInstruction = project.target.imageBase + 0x210;
    offset.evidence = openreverse::EvidenceLevel::Known;
    offset.provenance = {"user selection"};
    project.analysis.offsets.push_back(offset);

    openreverse::SignatureRecord signature;
    signature.stableId = "signature:fixture";
    signature.pattern = openreverse::PatternScanner::ParsePattern("48 8B ?? FF");
    signature.targetFunction = project.target.imageBase + 0x200;
    signature.targetOffset = 0x123;
    signature.sourceVersion = "fixture-v1";
    project.analysis.signatures.push_back(signature);

    openreverse::ProjectStructure structure;
    structure.stableId = "structure:200:1:rcx";
    structure.name = "FixtureState";
    structure.sourceFunctionRva = 0x200;
    structure.baseRegister = "rcx";
    structure.argumentIndex = 1;
    structure.estimatedSize = 0x20;
    structure.evidence = openreverse::EvidenceLevel::Inferred;
    structure.evidenceScore = 4;
    structure.accepted = true;
    openreverse::ProjectStructureField field;
    field.offset = 8;
    field.size = 4;
    field.name = "flags";
    field.type = "uint32_t";
    field.comment = "confirmed by the reviewer";
    structure.fields.push_back(field);
    project.analysis.structures.push_back(structure);
    project.user.structures.push_back(structure);
    project.user.functions.push_back({0x200, "ValidateFixture", "reviewed entry point"});
    project.user.bookmarks.push_back({0x210, "Validation branch", "inspect call", 0xFF33AA55});

    openreverse::ProjectMigrationDecision migration;
    migration.stableId = "migration:g_state";
    migration.kind = openreverse::OffsetKind::GlobalRva;
    migration.oldRva = 0x123;
    migration.newRva = 0x180;
    migration.oldValue = 0x1A8;
    migration.newValue = 0x1B0;
    migration.decision = openreverse::ProjectMigrationDecisionKind::Accepted;
    migration.evidence = {"unique signature", "matching CFG"};
    project.user.migrations.push_back(migration);
    project.user.settings["address.display"] = "module+rva";
    project.extensionState["org.openreverse.unknown"] =
        "{\"schema_version\":3,\"items\":[1,\"preserved\"]}";
    project.ui.currentRva = 0x210;
    project.ui.workspace = "editor";
    project.ui.openPanels = {"analysis", "bookmarks", "console"};
    project.hasVersionComparison = true;
    project.versionComparison.oldTarget = {"fixture-v1.exe", "old.exe", std::string(64, '1'),
        "x64", 1, 0x3000, 0x140000000ULL};
    project.versionComparison.newTarget = {"fixture-v2.exe", targetPath, project.target.sha256,
        "x64", 2, 0x3000, project.target.imageBase};
    openreverse::VersionFunctionMatch persistedMatch;
    persistedMatch.stableId = "function:0x200";
    persistedMatch.oldRva = 0x200;
    persistedMatch.oldName = "ValidateFixture";
    persistedMatch.suggestedState = openreverse::VersionMatchState::StrongCandidate;
    persistedMatch.decision = openreverse::VersionDecision::Accepted;
    persistedMatch.decisionNewRva = 0x240;
    openreverse::VersionFunctionCandidate persistedCandidate;
    persistedCandidate.newRva = 0x240;
    persistedCandidate.newName = "ValidateFixtureV2";
    persistedCandidate.similarityScore = 0.88;
    persistedCandidate.suggestedState = openreverse::VersionMatchState::StrongCandidate;
    persistedCandidate.evidence.push_back({openreverse::VersionEvidenceKind::NormalizedCode,
        0.9, 10, 11, "normalized code"});
    persistedCandidate.changes.instructionDelta = 1;
    persistedMatch.candidates.push_back(persistedCandidate);
    project.versionComparison.functions.push_back(persistedMatch);
    openreverse::VersionMigrationCandidate persistedMigration;
    persistedMigration.stableId = "offset:global:123";
    persistedMigration.kind = openreverse::VersionMigrationKind::Offset;
    persistedMigration.offsetKind = openreverse::OffsetKind::GlobalRva;
    persistedMigration.oldRva = 0x123;
    persistedMigration.newRva = 0x180;
    persistedMigration.suggestedState = openreverse::VersionMatchState::StrongCandidate;
    persistedMigration.decision = openreverse::VersionDecision::Rejected;
    persistedMigration.evidence.push_back({openreverse::VersionEvidenceKind::Globals,
        0.85, 2, 2, "matched global relationship"});
    project.versionComparison.migrations.push_back(persistedMigration);

    std::string serialized;
    Expect(openreverse::ProjectStore::Serialize(project, serialized, error) &&
           serialized.find("openreverse-project") != std::string::npos,
           "versioned OpenReverse projects serialize with integrity metadata");
    openreverse::OpenReverseProject parsed;
    Expect(openreverse::ProjectStore::Parse(serialized, parsed, error) &&
           parsed.user.functions.size() == 1 && parsed.user.bookmarks.size() == 1 &&
           parsed.user.structures.size() == 1 && parsed.user.migrations.size() == 1 &&
           parsed.analysis.offsets.size() == 1 && parsed.analysis.signatures.size() == 1 &&
           parsed.user.settings.at("address.display") == "module+rva" &&
           parsed.extensionState.at("org.openreverse.unknown") ==
               "{\"items\":[1,\"preserved\"],\"schema_version\":3}" &&
           parsed.ui.currentRva == 0x210 && parsed.hasVersionComparison &&
           parsed.versionComparison.functions.size() == 1 &&
           parsed.versionComparison.functions[0].decisionNewRva == 0x240 &&
           parsed.versionComparison.migrations[0].decision == openreverse::VersionDecision::Rejected,
           "project round-trip preserves annotations, analysis evidence, decisions, settings, and UI");

    auto previousComparisonProject = project;
    previousComparisonProject.versionComparison.algorithmVersion = 1;
    std::string previousComparisonJson;
    Expect(openreverse::ProjectStore::Serialize(previousComparisonProject,
               previousComparisonJson, error) &&
           openreverse::ProjectStore::Parse(previousComparisonJson, parsed, error) &&
           parsed.versionComparison.algorithmVersion == 1,
           "projects retain readable Version Intelligence v1 review decisions after the v2 upgrade");

    std::string canonicalState;
    Expect(openreverse::ProjectStore::ValidateExtensionState(
               "org.openreverse.example", "{\"enabled\":true}", canonicalState, error) &&
           canonicalState == "{\"enabled\":true}" &&
           !openreverse::ProjectStore::ValidateExtensionState(
               "../escape", "{}", canonicalState, error) &&
           !openreverse::ProjectStore::ValidateExtensionState(
               "org.openreverse.example", "[1,2,3]", canonicalState, error),
           "extension project state requires a bounded object scoped by a canonical extension ID");

    auto legacyProject = project;
    legacyProject.hasVersionComparison = false;
    legacyProject.versionComparison = {};
    std::string legacyJson;
    Expect(openreverse::ProjectStore::Serialize(legacyProject, legacyJson, error) &&
           openreverse::ProjectStore::Parse(legacyJson, parsed, error) && !parsed.hasVersionComparison,
           "version-1 projects without the additive Version Intelligence section remain compatible");

    Expect(openreverse::ProjectStore::SaveAtomic(projectPath, project, error),
           "project save publishes a new file atomically");
    project.user.functions[0].comment = "saved replacement";
    Expect(openreverse::ProjectStore::SaveAtomic(projectPath, project, error),
           "project save atomically replaces an existing project");
    openreverse::OpenReverseProject loaded;
    Expect(openreverse::ProjectStore::Load(projectPath, loaded, error) &&
           loaded.user.functions[0].comment == "saved replacement",
           "project load observes the complete replacement rather than a partial write");

    std::string corrupted = serialized;
    const size_t architecture = corrupted.find("\"architecture\": \"x64\"");
    if (architecture != std::string::npos) corrupted[architecture + 17] = 'y';
    Expect(!openreverse::ProjectStore::Parse(corrupted, parsed, error) &&
           error.find("integrity") != std::string::npos,
           "project corruption is rejected by the integrity digest");
    Expect(!openreverse::ProjectStore::Parse("{not-json", parsed, error) && !error.empty(),
           "malformed project JSON reports an explicit error");

    std::string unsupported = serialized;
    const size_t version = unsupported.find("\"version\": 1");
    if (version != std::string::npos) unsupported.replace(version, 12, "\"version\": 99");
    Expect(!openreverse::ProjectStore::Parse(unsupported, parsed, error) &&
           error.find("Unsupported") != std::string::npos,
           "unsupported project versions fail explicitly before integrity validation");

    auto verification = openreverse::ProjectStore::VerifyTarget(project);
    Expect(verification.status == openreverse::ProjectTargetVerificationStatus::Match,
           "project target verification accepts the matching SHA-256 identity");
    {
        const uint8_t changed[] = {9, 8, 7, 6};
        std::ofstream file(targetPath, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char*>(changed), sizeof(changed));
    }
    verification = openreverse::ProjectStore::VerifyTarget(project);
    Expect(verification.status == openreverse::ProjectTargetVerificationStatus::HashMismatch,
           "project target verification detects a changed target");
    DeleteFileA(targetPath.c_str());
    verification = openreverse::ProjectStore::VerifyTarget(project);
    Expect(verification.status == openreverse::ProjectTargetVerificationStatus::Missing,
           "project target verification distinguishes a missing target");

    openreverse::AnalysisSession session;
    session.SetLoadedProject(project, projectPath, true);
    Expect(session.FindFunctionAnnotation(0x200) != nullptr && !session.IsDirty(),
           "analysis session owns restored project annotations without marking them dirty");
    Expect(session.SetExtensionState("org.openreverse.example", "{\"value\":7}", error) &&
           session.ExtensionState("org.openreverse.example") &&
           *session.ExtensionState("org.openreverse.example") == "{\"value\":7}",
           "analysis sessions own bounded extension state without understanding its schema");
    Expect(!session.SetVersionDecision("function:0x200", openreverse::VersionDecision::Accepted, 0x999) &&
           session.SetVersionDecision("function:0x200", openreverse::VersionDecision::Rejected) &&
           session.SetVersionDecision("function:0x200", openreverse::VersionDecision::Accepted, 0x240) &&
           session.VersionIntelligence() &&
           session.VersionIntelligence()->functions[0].decision == openreverse::VersionDecision::Accepted &&
           session.VersionIntelligence()->functions[0].decisionNewRva == 0x240 &&
           session.IsDirty(), "analysis session persists explicit Version Intelligence decisions");
    openreverse::ModuleAnalysisResult result;
    result.module.baseAddress = 0x180000000ULL;
    result.module.size = 0x3000;
    result.offsets.push_back(offset);
    session.ApplyPersistedAnalysis(result);
    Expect(result.offsets.size() == 1 && result.offsets[0].address == 0x180000123ULL &&
           result.offsets[0].sourceFunction == 0x180000200ULL && result.signatures.size() == 1 &&
           result.signatures[0].targetFunction == 0x180000200ULL,
           "analysis session restores project evidence using RVAs at a new image base");
    session.SetLoadedProject(project, projectPath, false);
    Expect(session.RequiresSaveAs() && session.FindFunctionAnnotation(0x200) == nullptr &&
           session.Project().analysis.offsets.empty(),
           "changed-target sessions suppress target-bound state and require Save As");

    DeleteFileA(projectPath.c_str());
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

void TestExtensionBoundary()
{
    using namespace openreverse::extensions;
    SemanticVersion version;
    Expect(ParseSemanticVersion("1.2.3", version) && version.major == 1 &&
           version.minor == 2 && version.patch == 3,
           "extension semantic versions use an explicit three-component format");
    Expect(!ParseSemanticVersion("1.2.3.4", version) &&
           !ParseSemanticVersion("01.2.3", version),
           "extension semantic versions reject extra and non-canonical components");
    Expect(IsValidExtensionId("org.openreverse.example") &&
           !IsValidExtensionId("../example") && !IsValidExtensionId("Upper.Example"),
           "extension IDs reject traversal and non-canonical characters");

    TemporaryDirectory fixtures("extension-boundary");
    const auto root = fixtures.Path() / "extensions";
    std::filesystem::create_directories(root);
    const auto helloSource = std::filesystem::path(OPENREVERSE_TEST_HELLO_EXTENSION);
    const auto missingEntrypointSource =
        std::filesystem::path(OPENREVERSE_TEST_MISSING_ENTRYPOINT_EXTENSION);
    const auto failingSource = std::filesystem::path(OPENREVERSE_TEST_FAILING_EXTENSION);
    const auto stateSource = std::filesystem::path(OPENREVERSE_TEST_STATE_EXTENSION);
    Expect(std::filesystem::is_regular_file(helloSource) &&
           std::filesystem::is_regular_file(missingEntrypointSource) &&
           std::filesystem::is_regular_file(failingSource) &&
           std::filesystem::is_regular_file(stateSource),
           "extension compatibility DLL fixtures were built");

    const auto valid = root / "01-valid";
    WriteTextFile(valid / "manifest.json",
        ExtensionManifestText("org.openreverse.hello", "OpenReverseHelloExtension.dll"));
    std::filesystem::copy_file(helloSource, valid / "OpenReverseHelloExtension.dll");

    const auto state = root / "01b-state";
    WriteTextFile(state / "manifest.json",
        ExtensionManifestText("org.openreverse.state-fixture", "state.dll", 1, "2.0.0",
                              "\"project.extension_state\""));
    std::filesystem::copy_file(stateSource, state / "state.dll");

    const auto duplicate = root / "02-duplicate";
    WriteTextFile(duplicate / "manifest.json",
        ExtensionManifestText("org.openreverse.hello", "duplicate.dll"));
    WriteTextFile(root / "03-malformed" / "manifest.json", "{not-json");
    WriteTextFile(root / "04-api" / "manifest.json",
        ExtensionManifestText("org.openreverse.api", "api.dll", 99));
    WriteTextFile(root / "05-host" / "manifest.json",
        ExtensionManifestText("org.openreverse.host", "host.dll", 1, "99.0.0"));
    WriteTextFile(root / "06-unknown" / "manifest.json",
        ExtensionManifestText("org.openreverse.unknown", "unknown.dll", 1, "2.0.0",
                              "\"unknown.capability\""));
    WriteTextFile(root / "07-unsupported" / "manifest.json",
        ExtensionManifestText("org.openreverse.network", "network.dll", 1, "2.0.0",
                              "\"network\""));
    WriteTextFile(root / "08-missing" / "manifest.json",
        ExtensionManifestText("org.openreverse.missing", "missing.dll"));

    const auto noEntrypoint = root / "09-entrypoint";
    WriteTextFile(noEntrypoint / "manifest.json",
        ExtensionManifestText("org.openreverse.noentry", "missing-entrypoint.dll", 1,
                              "2.0.0", ""));
    std::filesystem::copy_file(missingEntrypointSource, noEntrypoint / "missing-entrypoint.dll");

    const auto failing = root / "10-failing";
    WriteTextFile(failing / "manifest.json",
        ExtensionManifestText("org.openreverse.failing", "failing.dll", 1, "2.0.0", ""));
    std::filesystem::copy_file(failingSource, failing / "failing.dll");
    WriteTextFile(root / "11-traversal" / "manifest.json",
        ExtensionManifestText("org.openreverse.traversal", "..\\\\escape.dll"));
    std::filesystem::copy_file(helloSource, root / "random-unmanifested.dll");

    uint64_t navigatedAddress = 0;
    std::map<std::string, std::string> projectState;
    ExtensionHostServices services;
    services.currentTarget = [](ExtensionTargetSnapshot& target) {
        target.name = "fixture.exe";
        target.path = "fixture.exe";
        target.sha256 = std::string(64, 'a');
        target.architecture = OPENREVERSE_ARCHITECTURE_X64;
        target.imageBase = 0x140000000ULL;
        target.imageSize = 0x3000;
        target.currentAddress = 0x140001000ULL;
        target.analysisRevision = 7;
        target.peTimestamp = 0x12345678;
        target.functionCount = 2;
        return true;
    };
    services.functionByIndex = [](uint32_t index, ExtensionFunctionSnapshot& function) {
        if (index >= 2) return false;
        function.name = index == 0 ? "entry" : "helper";
        function.address = 0x140001000ULL + index * 0x100;
        function.rva = 0x1000 + index * 0x100;
        function.size = 16;
        function.instructionCount = 4;
        function.basicBlockCount = 1;
        function.directCallCount = 0;
        function.boundaryKnown = true;
        return true;
    };
    services.navigateToAddress = [&](uint64_t address) {
        navigatedAddress = address;
        return address >= 0x140000000ULL && address < 0x140003000ULL;
    };
    services.hasProject = []() { return true; };
    services.projectPath = []() { return std::string("fixture.orev"); };
    services.getExtensionState = [&](const std::string& id, std::string& state) {
        const auto found = projectState.find(id);
        if (found == projectState.end()) return false;
        state = found->second;
        return true;
    };
    services.setExtensionState = [&](const std::string& id, const std::string& state,
                                     std::string&) {
        projectState[id] = state;
        return true;
    };

    ExtensionManager manager;
    manager.Configure(services, {2, 0, 0});
    Expect(!manager.DiscoverAndLoad(root),
           "mixed valid and invalid extension directories report a bounded aggregate failure");
    const auto loaded = manager.LoadedExtensions();
    Expect(loaded.size() == 2 &&
           std::any_of(loaded.begin(), loaded.end(), [](const LoadedExtensionInfo& extension) {
               return extension.id == "org.openreverse.hello";
           }) &&
           std::any_of(loaded.begin(), loaded.end(), [](const LoadedExtensionInfo& extension) {
               return extension.id == "org.openreverse.state-fixture";
           }),
           "only compatible manifest-backed extensions load");
    Expect(projectState["org.openreverse.state-fixture"] ==
               "{\"schema\":1,\"value\":\"fixture\"}",
           "extension-specific project state crosses the ABI in both directions");
    const auto hasDiagnostic = [&](ExtensionDiagnosticKind kind) {
        return std::any_of(manager.Diagnostics().begin(), manager.Diagnostics().end(),
            [&](const ExtensionDiagnostic& diagnostic) { return diagnostic.kind == kind; });
    };
    Expect(hasDiagnostic(ExtensionDiagnosticKind::DuplicateId) &&
           hasDiagnostic(ExtensionDiagnosticKind::ManifestError) &&
           hasDiagnostic(ExtensionDiagnosticKind::IncompatibleApi) &&
           hasDiagnostic(ExtensionDiagnosticKind::IncompatibleHost) &&
           hasDiagnostic(ExtensionDiagnosticKind::UnsupportedCapability) &&
           hasDiagnostic(ExtensionDiagnosticKind::MissingModule) &&
           hasDiagnostic(ExtensionDiagnosticKind::MissingEntrypoint) &&
           hasDiagnostic(ExtensionDiagnosticKind::InitializationFailure),
           "extension diagnostics distinguish all compatibility and initialization failures");

    const auto commands = manager.Commands();
    bool available = false;
    std::string error;
    Expect(commands.size() == 1 &&
           manager.IsCommandAvailable(commands[0].id, available, error) == OPENREVERSE_OK &&
           available && manager.ExecuteCommand(commands[0].id, error) == OPENREVERSE_OK &&
           navigatedAddress == 0x140001000ULL,
           "the example command queries analysis and requests controlled navigation");
    const auto panels = manager.Panels();
    std::string panelText;
    Expect(panels.size() == 1 &&
           manager.RenderPanelText(panels[0].id, panelText, error) == OPENREVERSE_OK &&
           panelText.find("Detected functions: 2") != std::string::npos,
           "the example panel returns bounded host-rendered UTF-8 text");
    manager.NotifySessionChanged(9, true);
    Expect(hasDiagnostic(ExtensionDiagnosticKind::CallbackFailure),
           "a failing lifecycle callback is diagnosed without corrupting the host");
    manager.NotifyProjectOpened();
    manager.NotifyProjectClosed();
    manager.Shutdown();

    const auto emptyRoot = fixtures.Path() / "empty";
    std::filesystem::create_directories(emptyRoot);
    ExtensionManager emptyManager;
    emptyManager.Configure(services, {2, 0, 0});
    Expect(emptyManager.DiscoverAndLoad(emptyRoot) && emptyManager.LoadedExtensions().empty(),
           "Community operates normally with zero installed extensions");

    const auto callbackRoot = fixtures.Path() / "callback" / "valid";
    WriteTextFile(callbackRoot / "manifest.json",
        ExtensionManifestText("org.openreverse.hello", "OpenReverseHelloExtension.dll"));
    std::filesystem::copy_file(helloSource, callbackRoot / "OpenReverseHelloExtension.dll");
    ExtensionHostServices unavailableServices = services;
    unavailableServices.currentTarget = [](ExtensionTargetSnapshot&) { return false; };
    ExtensionManager callbackManager;
    callbackManager.Configure(std::move(unavailableServices), {2, 0, 0});
    Expect(callbackManager.DiscoverAndLoad(callbackRoot.parent_path()) &&
           callbackManager.IsCommandAvailable("org.openreverse.hello.navigate-first",
                                              available, error) ==
               OPENREVERSE_ERROR_NO_ACTIVE_SESSION && !available,
           "extension callback failures remain structured and do not corrupt the host");
    callbackManager.Shutdown();
}

} // namespace

int main()
{
    TestSharedUtilities();
    TestInstructionSemantics();
    TestDiaSymbols();
    TestPEMapping();
    TestAddressSpacesAndRuntimeFunctions();
    TestMappedAnalysisPipeline();
    TestMalformedPEs();
    TestBoundedParserMutationCorpus();
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
    TestVersionIntelligence();
    TestVersionIntelligenceScaling();
    TestProjectPersistence();
    TestDumpImportAndDeniedAccess();
    TestExtensionBoundary();

    if (failures != 0)
    {
        std::cerr << failures << " core test(s) failed\n";
        return 1;
    }
    std::cout << "All OpenReverse core tests passed\n";
    return 0;
}
