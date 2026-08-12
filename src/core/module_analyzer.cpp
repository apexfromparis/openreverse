#include "module_analyzer.h"

#include "core/memory_reader.h"
#include "core/signature_engine.h"

#include <algorithm>
#include <limits>
#include <map>
#include <utility>
#include <sstream>

namespace openreverse {

namespace {

void BuildTypedOffsets(ModuleAnalysisResult& result)
{
    result.offsets.clear();
    const auto& module = result.module;
    for (const auto& function : result.functions)
    {
        OffsetRecord offset;
        std::ostringstream stable;
        stable << "function:" << std::hex << (function.startAddress - module.baseAddress);
        offset.stableId = stable.str();
        offset.name = function.name;
        offset.kind = function.isExported ? OffsetKind::ExportRva : OffsetKind::FunctionRva;
        offset.address = function.startAddress;
        offset.rva = function.startAddress - module.baseAddress;
        offset.module = module.name;
        offset.sourceFunction = function.startAddress;
        offset.evidence = function.boundaryKnown ? EvidenceLevel::Known :
            function.source == FunctionSource::Heuristic ? EvidenceLevel::Heuristic : EvidenceLevel::Inferred;
        offset.evidenceScore = function.boundaryKnown ? 3U :
            function.source == FunctionSource::Heuristic ? 1U : 2U;
        offset.provenance.push_back(function.boundaryKnown ? "runtime function boundary" :
            function.source == FunctionSource::Export ? "PE export" :
            function.source == FunctionSource::EntryPoint ? "PE entry point" :
            function.source == FunctionSource::DirectCall ? "decoded direct call" : "heuristic function seed");
        result.offsets.push_back(std::move(offset));
    }
    for (const auto& global : result.globals)
    {
        OffsetRecord offset;
        std::ostringstream stable;
        stable << "global:" << std::hex << global.rva;
        offset.stableId = stable.str();
        offset.name = global.name;
        offset.kind = OffsetKind::GlobalRva;
        offset.address = global.address;
        offset.rva = global.rva;
        offset.module = module.name;
        offset.section = global.sectionName;
        offset.sourceInstruction = global.accessSites.empty() ? 0 : global.accessSites.front();
        offset.evidence = global.evidence;
        offset.evidenceScore = global.evidenceScore;
        offset.provenance.push_back("resolved operand Xrefs");
        result.offsets.push_back(std::move(offset));
    }
    for (const auto& field : result.fieldAccesses)
    {
        OffsetRecord offset;
        std::ostringstream stable;
        stable << "field:" << std::hex << field.functionAddress << ':' << std::dec
               << static_cast<unsigned>(field.argumentIndex) << ':' << field.displacement;
        offset.stableId = stable.str();
        offset.name = field.argumentIndex != 0
            ? "Arg" + std::to_string(field.argumentIndex) + "_field_" + std::to_string(field.displacement)
            : "field_" + std::to_string(field.displacement);
        offset.kind = OffsetKind::StructureField;
        offset.fieldOffset = field.displacement;
        offset.module = module.name;
        offset.sourceFunction = field.functionAddress;
        offset.sourceInstruction = field.instructionAddress;
        offset.accessType = field.access;
        offset.operandWidth = field.operandSize;
        offset.evidence = field.argumentIndex != 0 ? EvidenceLevel::Inferred : EvidenceLevel::Heuristic;
        offset.evidenceScore = field.argumentIndex != 0 ? 2U : 1U;
        offset.provenance.push_back(field.argumentIndex != 0
            ? "Windows x64 argument-origin propagation" : "decoded memory operand");
        result.offsets.push_back(std::move(offset));
    }
}

} // namespace

ModuleAnalysisResult ModuleAnalyzer::AnalyzeLive(HANDLE processHandle, const ModuleInfo& module,
                                                  bool is64Bit, const ModuleAnalysisOptions& options,
                                                  const CancellationToken* cancellation,
                                                  const ProgressCallback& progress) const
{
    ModuleAnalysisResult result;
    result.module = module;
    if (!processHandle || module.baseAddress == 0 || module.size == 0 ||
        options.maxCodeBytes == 0 || options.maxInstructions == 0 || options.maxFunctions == 0)
    {
        result.error = "Invalid live module analysis input";
        return result;
    }

    const auto started = std::chrono::steady_clock::now();
    const auto shouldStop = [&] {
        if (cancellation && cancellation->IsCancellationRequested())
        {
            result.cancelled = true;
            return true;
        }
        if (options.maxDuration.count() > 0 &&
            std::chrono::steady_clock::now() - started >= options.maxDuration)
        {
            result.timeBudgetReached = true;
            return true;
        }
        return false;
    };

    PEParser parser;
    result.pe = parser.Parse(processHandle, module.baseAddress, module.size);
    const auto peFinished = std::chrono::steady_clock::now();
    result.peDuration = std::chrono::duration_cast<std::chrono::milliseconds>(peFinished - started);
    if (!result.pe.valid)
    {
        result.error = "Malformed or inaccessible live PE metadata";
        return result;
    }

    Disassembler disassembler;
    if (!disassembler.Init(is64Bit))
    {
        result.error = "Capstone initialization failed";
        return result;
    }
    FunctionAnalyzer functionAnalyzer;
    XRefScanner xrefScanner;
    StringScanner stringScanner;
    MemoryReader memoryReader;

    size_t remainingCode = options.maxCodeBytes;
    size_t remainingInstructions = options.maxInstructions;
    std::map<uint64_t, FunctionInfo> functions;
    std::vector<std::pair<uint64_t, uint64_t>> analyzedRanges;
    size_t executableSections = 0;
    for (const auto& section : result.pe.sections)
        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) ++executableSections;
    size_t executableIndex = 0;

    for (const auto& section : result.pe.sections)
    {
        if (shouldStop() || remainingCode == 0 || remainingInstructions == 0)
            break;
        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            continue;
        ++executableIndex;
        const uint64_t sectionSize = std::max<uint64_t>(section.virtualSize, section.rawDataSize);
        if (sectionSize == 0 || section.virtualAddress > (std::numeric_limits<uint64_t>::max)() - module.baseAddress)
            continue;

        auto read = memoryReader.ReadReadableBlocks(processHandle, module.baseAddress + section.virtualAddress,
                                                     sectionSize, remainingCode);
        remainingCode -= std::min(remainingCode, read.bytesRead);
        result.codeBytesAnalyzed += read.bytesRead;
        for (const auto& block : read.blocks)
        {
            if (shouldStop() || block.bytes.empty()) break;
            if (block.bytes.size() > (std::numeric_limits<uint64_t>::max)() - block.baseAddress)
                continue;
            analyzedRanges.push_back({block.baseAddress, block.baseAddress + block.bytes.size()});
            if (functions.size() < options.maxFunctions)
            {
                auto discovered = functionAnalyzer.DiscoverFunctions(block.bytes.data(), block.bytes.size(),
                    block.baseAddress, is64Bit, options.maxFunctions - functions.size(), 0);
                for (auto& function : discovered)
                {
                    functions.emplace(function.startAddress, std::move(function));
                    if (functions.size() >= options.maxFunctions) break;
                }
            }
            if (shouldStop() || remainingInstructions == 0) break;
            const auto instructions = disassembler.Disassemble(block.bytes.data(), block.bytes.size(),
                block.baseAddress, std::min(remainingInstructions, block.bytes.size()));
            remainingInstructions -= std::min(remainingInstructions, instructions.size());
            xrefScanner.ScanInstructions(instructions, module.name);
            auto fields = FindFieldAccesses(
                instructions, 100000 - std::min<size_t>(result.fieldAccesses.size(), 100000));
            result.fieldAccesses.insert(result.fieldAccesses.end(), fields.begin(), fields.end());
        }
        if (progress && executableSections != 0)
            progress(0.6f * static_cast<float>(executableIndex) / executableSections);
    }
    result.codeBudgetReached = remainingCode == 0;
    result.instructionBudgetReached = remainingInstructions == 0;
    result.functionLimitReached = functions.size() >= options.maxFunctions;
    const auto codeFinished = std::chrono::steady_clock::now();
    result.codeDuration = std::chrono::duration_cast<std::chrono::milliseconds>(codeFinished - peFinished);

    if (result.cancelled)
        return result;
    if (analyzedRanges.empty())
    {
        result.error = "No readable executable section bytes were available";
        return result;
    }

    const auto isAnalyzedAddress = [&](uint64_t address) {
        return std::any_of(analyzedRanges.begin(), analyzedRanges.end(), [address](const auto& range) {
            return address >= range.first && address < range.second;
        });
    };

    for (auto& pair : functions)
        result.functions.push_back(std::move(pair.second));

    result.functions = functionAnalyzer.DiscoverFunctionsFromRuntimeFunctions(
        result.functions, module.baseAddress, result.pe.runtimeFunctions, is64Bit);

    std::vector<uint64_t> exportAddresses;
    for (const auto& entry : result.pe.exports)
    {
        if (entry.rva > (std::numeric_limits<uint64_t>::max)() - module.baseAddress) continue;
        const uint64_t address = module.baseAddress + entry.rva;
        if (!entry.isForwarder && isAnalyzedAddress(address)) exportAddresses.push_back(address);
    }
    const uint64_t entryAddress = result.pe.entryPoint <= (std::numeric_limits<uint64_t>::max)() - module.baseAddress
        ? module.baseAddress + result.pe.entryPoint : 0;
    result.functions = functionAnalyzer.DiscoverFunctionsFromPE(result.functions,
        isAnalyzedAddress(entryAddress) ? entryAddress : 0, exportAddresses, is64Bit);

    std::vector<uint64_t> callTargets;
    for (const auto& xref : xrefScanner.GetAllEntries())
        if (xref.type == XRefType::Call && isAnalyzedAddress(xref.toAddress))
            callTargets.push_back(xref.toAddress);
    for (const auto& range : analyzedRanges)
    {
        if (shouldStop()) break;
        result.functions = functionAnalyzer.DiscoverFunctionsFromXRefs(
            result.functions, callTargets, range.first, range.second, is64Bit, options.maxFunctions);
    }
    if (result.functions.size() > options.maxFunctions) result.functions.resize(options.maxFunctions);
    result.functionLimitReached = result.functionLimitReached ||
        result.functions.size() >= options.maxFunctions;

    for (const auto& entry : result.pe.exports)
    {
        if (entry.isForwarder) continue;
        const uint64_t address = module.baseAddress + entry.rva;
        auto function = std::lower_bound(result.functions.begin(), result.functions.end(), address,
            [](const FunctionInfo& value, uint64_t target) { return value.startAddress < target; });
        if (function != result.functions.end() && function->startAddress == address && !entry.name.empty())
        {
            function->name = entry.name;
            function->isExported = true;
        }
    }

    size_t remainingStrings = options.maxStringBytes;
    size_t readableSectionCount = 0;
    for (const auto& section : result.pe.sections)
        if ((section.characteristics & IMAGE_SCN_MEM_READ) != 0 && section.rawDataSize != 0) ++readableSectionCount;
    size_t readableIndex = 0;
    for (const auto& section : result.pe.sections)
    {
        if (shouldStop() || remainingStrings == 0 || result.strings.size() >= options.maxStrings)
            break;
        if ((section.characteristics & IMAGE_SCN_MEM_READ) == 0 || section.rawDataSize == 0)
            continue;
        ++readableIndex;
        auto read = memoryReader.ReadReadableBlocks(processHandle, module.baseAddress + section.virtualAddress,
                                                     section.rawDataSize, remainingStrings);
        remainingStrings -= std::min(remainingStrings, read.bytesRead);
        result.stringBytesAnalyzed += read.bytesRead;
        for (const auto& block : read.blocks)
        {
            if (shouldStop()) break;
            auto found = stringScanner.ScanBuffer(block.bytes.data(), block.bytes.size(), block.baseAddress,
                4, true, true, options.maxStrings - result.strings.size());
            result.strings.insert(result.strings.end(), found.begin(), found.end());
            if (result.strings.size() >= options.maxStrings) break;
        }
        if (progress && readableSectionCount != 0)
            progress(0.6f + 0.35f * static_cast<float>(readableIndex) / readableSectionCount);
    }
    result.stringBudgetReached = remainingStrings == 0;
    const auto stringsFinished = std::chrono::steady_clock::now();
    result.stringDuration = std::chrono::duration_cast<std::chrono::milliseconds>(stringsFinished - codeFinished);

    result.xrefs = xrefScanner.GetAllEntries();
    AssignXRefFunctions(result.xrefs, result.functions);
    result.globals = FindGlobalCandidates(module, result.pe, result.xrefs);
    AssignFieldFunctions(result.fieldAccesses, result.functions);
    result.structures = InferStructures(result.fieldAccesses);
    BuildTypedOffsets(result);
    for (auto& function : result.functions)
        function.xrefCount = static_cast<int>(xrefScanner.FindXRefsTo(function.startAddress).size());

    if (progress) progress(1.0f);
    result.totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    result.success = !result.cancelled && result.error.empty();
    return result;
}

ModuleAnalysisResult ModuleAnalyzer::AnalyzeMappedImage(
    const std::vector<uint8_t>& mappedImage, size_t sourceFileSize,
    const ModuleInfo& module, const PEInfo& pe, const ModuleAnalysisOptions& options,
    const CancellationToken* cancellation, const ProgressCallback& progress) const
{
    ModuleAnalysisResult result;
    result.module = module;
    result.pe = pe;
    if (!pe.valid || mappedImage.empty() || module.baseAddress == 0 || module.size == 0 ||
        mappedImage.size() < pe.sizeOfImage || module.baseAddress != pe.imageBase ||
        options.maxCodeBytes == 0 || options.maxInstructions == 0 || options.maxFunctions == 0)
    {
        result.error = "Invalid mapped-image analysis input";
        return result;
    }

    const auto started = std::chrono::steady_clock::now();
    const auto shouldStop = [&] {
        if (cancellation && cancellation->IsCancellationRequested())
        {
            result.cancelled = true;
            return true;
        }
        if (options.maxDuration.count() > 0 &&
            std::chrono::steady_clock::now() - started >= options.maxDuration)
        {
            result.timeBudgetReached = true;
            return true;
        }
        return false;
    };

    Disassembler disassembler;
    if (!disassembler.Init(pe.is64bit))
    {
        result.error = "Capstone initialization failed";
        return result;
    }
    FunctionAnalyzer functionAnalyzer;
    XRefScanner xrefScanner;
    StringScanner stringScanner;
    std::vector<Instruction> allInstructions;
    std::vector<std::pair<uint64_t, uint64_t>> executableRanges;
    size_t remainingCode = options.maxCodeBytes;
    size_t remainingInstructions = options.maxInstructions;
    size_t executableSections = 0;
    for (const auto& section : pe.sections)
        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) ++executableSections;
    size_t executableIndex = 0;

    for (const auto& section : pe.sections)
    {
        if (shouldStop() || remainingCode == 0 || remainingInstructions == 0) break;
        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
            section.virtualAddress >= mappedImage.size())
            continue;
        ++executableIndex;
        const size_t sectionSize = std::min<size_t>({
            static_cast<size_t>(std::max(section.virtualSize, section.rawDataSize)),
            mappedImage.size() - section.virtualAddress, remainingCode});
        if (sectionSize == 0) continue;

        const uint64_t sectionBase = module.baseAddress + section.virtualAddress;
        executableRanges.push_back({sectionBase, sectionBase + sectionSize});
        const auto instructions = disassembler.Disassemble(
            mappedImage.data() + section.virtualAddress, sectionSize, sectionBase,
            std::min(remainingInstructions, sectionSize));
        remainingCode -= sectionSize;
        remainingInstructions -= std::min(remainingInstructions, instructions.size());
        result.codeBytesAnalyzed += sectionSize;
        xrefScanner.ScanInstructions(instructions, module.name);
        auto fields = FindFieldAccesses(
            instructions, 100000 - std::min<size_t>(result.fieldAccesses.size(), 100000));
        result.fieldAccesses.insert(result.fieldAccesses.end(), fields.begin(), fields.end());
        allInstructions.insert(allInstructions.end(), instructions.begin(), instructions.end());

        if (result.functions.size() < options.maxFunctions)
        {
            auto heuristic = functionAnalyzer.DiscoverFunctions(
                mappedImage.data() + section.virtualAddress, sectionSize, sectionBase, pe.is64bit,
                options.maxFunctions - result.functions.size(), 0);
            result.functions.insert(result.functions.end(), heuristic.begin(), heuristic.end());
        }
        if (progress && executableSections != 0)
            progress(0.55f * static_cast<float>(executableIndex) / executableSections);
    }
    result.codeBudgetReached = remainingCode == 0;
    result.instructionBudgetReached = remainingInstructions == 0;
    if (result.cancelled) return result;
    if (executableRanges.empty())
    {
        result.error = "Mapped image has no analyzable executable section";
        return result;
    }

    result.functions = functionAnalyzer.DiscoverFunctionsFromRuntimeFunctions(
        result.functions, module.baseAddress, pe.runtimeFunctions, pe.is64bit);
    std::vector<uint64_t> exports;
    for (const auto& entry : pe.exports)
        if (!entry.isForwarder) exports.push_back(module.baseAddress + entry.rva);
    const uint64_t entryAddress = pe.entryPoint != 0 ? module.baseAddress + pe.entryPoint : 0;
    result.functions = functionAnalyzer.DiscoverFunctionsFromPE(
        result.functions, entryAddress, exports, pe.is64bit);

    std::vector<uint64_t> calls;
    for (const auto& xref : xrefScanner.GetAllEntries())
        if (xref.type == XRefType::Call) calls.push_back(xref.toAddress);
    for (const auto& range : executableRanges)
        result.functions = functionAnalyzer.DiscoverFunctionsFromXRefs(
            result.functions, calls, range.first, range.second, pe.is64bit, options.maxFunctions);
    if (result.functions.size() > options.maxFunctions) result.functions.resize(options.maxFunctions);
    result.functionLimitReached = result.functions.size() >= options.maxFunctions;

    std::sort(result.functions.begin(), result.functions.end(),
        [](const FunctionInfo& left, const FunctionInfo& right) {
            return left.startAddress < right.startAddress;
        });
    for (size_t index = 0; index < result.functions.size(); ++index)
    {
        auto& function = result.functions[index];
        if (function.analysisLimit > function.startAddress) continue;
        uint64_t sectionEnd = function.startAddress;
        for (const auto& range : executableRanges)
            if (function.startAddress >= range.first && function.startAddress < range.second)
                sectionEnd = range.second;
        if (sectionEnd > function.startAddress)
        {
            function.analysisLimit = std::min<uint64_t>(sectionEnd,
                function.startAddress + std::min<uint64_t>(4096, sectionEnd - function.startAddress));
            if (index + 1 < result.functions.size() &&
                result.functions[index + 1].startAddress < function.analysisLimit)
                function.analysisLimit = result.functions[index + 1].startAddress;
        }
    }
    for (const auto& entry : pe.exports)
    {
        if (entry.isForwarder) continue;
        const uint64_t address = module.baseAddress + entry.rva;
        auto function = std::lower_bound(result.functions.begin(), result.functions.end(), address,
            [](const FunctionInfo& value, uint64_t target) { return value.startAddress < target; });
        if (function != result.functions.end() && function->startAddress == address && !entry.name.empty())
            function->name = entry.name;
    }

    result.xrefs = xrefScanner.GetAllEntries();
    AssignXRefFunctions(result.xrefs, result.functions);
    result.globals = FindGlobalCandidates(module, pe, result.xrefs);
    AssignFieldFunctions(result.fieldAccesses, result.functions);
    result.structures = InferStructures(result.fieldAccesses);
    BuildTypedOffsets(result);
    for (auto& function : result.functions)
        function.xrefCount = static_cast<int>(std::count_if(result.xrefs.begin(), result.xrefs.end(),
            [&](const XRefEntry& xref) { return xref.toAddress == function.startAddress; }));

    size_t remainingStrings = options.maxStringBytes;
    size_t readableSections = 0;
    for (const auto& section : pe.sections)
        if ((section.characteristics & IMAGE_SCN_MEM_READ) != 0) ++readableSections;
    size_t readableIndex = 0;
    for (const auto& section : pe.sections)
    {
        if (shouldStop() || remainingStrings == 0 || result.strings.size() >= options.maxStrings) break;
        if ((section.characteristics & IMAGE_SCN_MEM_READ) == 0 ||
            section.virtualAddress >= mappedImage.size())
            continue;
        ++readableIndex;
        const size_t sectionSize = std::min<size_t>({
            static_cast<size_t>(std::max(section.virtualSize, section.rawDataSize)),
            mappedImage.size() - section.virtualAddress, remainingStrings});
        remainingStrings -= sectionSize;
        result.stringBytesAnalyzed += sectionSize;
        auto strings = stringScanner.ScanBuffer(
            mappedImage.data() + section.virtualAddress, sectionSize,
            module.baseAddress + section.virtualAddress, 4, true, true,
            options.maxStrings - result.strings.size());
        result.strings.insert(result.strings.end(), strings.begin(), strings.end());
        if (progress && readableSections != 0)
            progress(0.55f + 0.25f * static_cast<float>(readableIndex) / readableSections);
    }
    result.stringBudgetReached = remainingStrings == 0;

    std::string identityError;
    ComputeModuleIdentity(mappedImage, pe, module.name, result.identity, identityError);

    SignatureEngine signatureEngine;
    std::sort(allInstructions.begin(), allInstructions.end(),
        [](const Instruction& left, const Instruction& right) { return left.address < right.address; });
    size_t generatedSignatures = 0;
    for (const auto& function : result.functions)
    {
        if (generatedSignatures >= 256 || shouldStop()) break;
        const auto instruction = std::lower_bound(allInstructions.begin(), allInstructions.end(),
            function.startAddress, [](const Instruction& value, uint64_t address) {
                return value.address < address;
            });
        if (instruction == allInstructions.end() || instruction->address != function.startAddress) continue;
        SignatureRelationship relationship;
        relationship.kind = SignatureTargetKind::FunctionRva;
        SignatureGenerationOptions generation;
        generation.imageBase = module.baseAddress;
        generation.imageSize = module.size;
        auto signature = signatureEngine.Generate(allInstructions,
            static_cast<size_t>(instruction - allInstructions.begin()), relationship, generation);
        if (signature.pattern.empty()) continue;
        std::ostringstream stable;
        stable << "signature:function:" << std::hex << (function.startAddress - module.baseAddress);
        signature.stableId = stable.str();
        signature.targetFunction = function.startAddress;
        signature.targetOffset = function.startAddress - module.baseAddress;
        signatureEngine.Evaluate(signature, mappedImage, pe, sourceFileSize);
        result.signatures.push_back(std::move(signature));
        ++generatedSignatures;
    }

    if (progress) progress(1.0f);
    result.totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    result.success = !result.cancelled && result.error.empty();
    return result;
}

} // namespace openreverse
