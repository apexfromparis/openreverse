#include "module_analyzer.h"

#include "core/memory_reader.h"

#include <algorithm>
#include <limits>
#include <map>
#include <utility>

namespace openreverse {

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
    result.globals = FindGlobalCandidates(module, result.pe, result.xrefs);
    AssignFieldFunctions(result.fieldAccesses, result.functions);
    result.structures = InferStructures(result.fieldAccesses);
    for (auto& function : result.functions)
        function.xrefCount = static_cast<int>(xrefScanner.FindXRefsTo(function.startAddress).size());

    if (progress) progress(1.0f);
    result.totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    result.success = !result.cancelled && result.error.empty();
    return result;
}

} // namespace openreverse
