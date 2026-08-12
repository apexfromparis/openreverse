#include "automator.h"
#include "core/module_analyzer.h"
#include "utils/logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace openreverse {

AutoAnalysisResult Automator::AnalyzeProcess(Application& app, DWORD pid, const std::string& processName)
{
    AutoAnalysisResult res;
    res.targetPid = pid;
    res.targetProcessName = processName;

    if ((!app.isAttached || app.attachedPID != pid || !app.processHandle) && !app.AttachToProcess(pid))
    {
        Logger::Get().Log(LogLevel::Error, "Automator failed to attach to PID %d", pid);
        return res;
    }

    res.targetProcessName = app.attachedProcessName;

    auto* mod = app.moduleManager.FindModuleByAddress(app.currentAddress);
    if (!mod && !app.moduleManager.GetModules().empty())
        mod = const_cast<ModuleInfo*>(&app.moduleManager.GetModules()[0]);

    if (!mod)
        return res;

    res.baseAddress = mod->baseAddress;

    ModuleAnalysisOptions options;
    options.maxFunctions = 200;
    options.maxStrings = 2000;
    ModuleAnalyzer moduleAnalyzer;
    auto analysis = moduleAnalyzer.AnalyzeLive(app.processHandle, *mod, app.is64Bit, options);
    if (!analysis.success)
    {
        Logger::Get().Log(LogLevel::Error, "Automator failed to analyze %s: %s",
                          mod->name.c_str(), analysis.error.c_str());
        return res;
    }

    Disassembler disassembler;
    if (!disassembler.Init(app.is64Bit))
        return res;
    FunctionAnalyzer functionAnalyzer;

    res.stringsFound = analysis.strings.size();
    for (const auto& sr : analysis.strings)
    {
        if (sr.category == "URL")
            res.urls.push_back(sr.value);
        else if (sr.category == "Registry Path")
            res.registryPaths.push_back(sr.value);
    }

    res.functionsDiscovered = analysis.functions.size();
    res.totalXrefs = analysis.xrefs.size();

    size_t maxReportFuncs = 15;
    for (size_t i = 0; i < analysis.functions.size() && res.keyFunctions.size() < maxReportFuncs; ++i)
    {
        auto read = app.memoryReader.ReadReadableBlocks(app.processHandle,
            analysis.functions[i].startAddress, 4096, 4096);
        if (read.blocks.empty() || read.blocks[0].baseAddress != analysis.functions[i].startAddress)
            continue;
        auto fi = functionAnalyzer.AnalyzeFunction(read.blocks[0].bytes.data(), read.blocks[0].bytes.size(),
            analysis.functions[i].startAddress, analysis.functions[i].startAddress,
            disassembler, app.is64Bit, 4096);
        if (!analysis.functions[i].name.empty()) fi.name = analysis.functions[i].name;

        if (fi.cyclomaticComplexity >= 2 || i < 5)
        {
            AutoAnalysisResult::FunctionSummary fs;
            fs.address = fi.startAddress;
            fs.name = fi.name;
            fs.analyzedSize = fi.analyzedSize;
            fs.complexity = fi.cyclomaticComplexity;
            fs.xrefCount = static_cast<int>(std::count_if(analysis.xrefs.begin(), analysis.xrefs.end(),
                [&fi](const XRefEntry& xref) { return xref.toAddress == fi.startAddress; }));
            fs.assemblySummary = functionAnalyzer.GenerateAssemblySummary(fi, app.is64Bit);
            res.keyFunctions.push_back(fs);
        }
    }

    res.success = true;
    return res;
}

std::string Automator::FormatReport(const AutoAnalysisResult& res)
{
    std::ostringstream ss;
    ss << "# OpenReverse Automated Analysis Report\n\n";
    ss << "- **Target Process**: `" << res.targetProcessName << "` (PID: `" << res.targetPid << "`)\n";
    ss << "- **Base Address**: `0x" << std::uppercase << std::hex << res.baseAddress << "`\n";
    ss << "- **Functions Discovered**: `" << std::dec << res.functionsDiscovered << "`\n";
    ss << "- **Cross-References (XREFs)**: `" << res.totalXrefs << "`\n";
    ss << "- **Strings Discovered**: `" << res.stringsFound << "`\n\n";

    if (!res.urls.empty())
    {
        ss << "## Observed URLs\n";
        for (const auto& url : res.urls)
            ss << "- `" << url << "`\n";
        ss << "\n";
    }

    if (!res.registryPaths.empty())
    {
        ss << "## Observed Registry Paths\n";
        for (const auto& reg : res.registryPaths)
            ss << "- `" << reg << "`\n";
        ss << "\n";
    }

    ss << "## Decoded control-flow evidence (key functions)\n\n";
    for (const auto& fn : res.keyFunctions)
    {
        ss << "### Function `" << fn.name << "` (0x" << std::uppercase << std::hex << fn.address << ")\n";
        ss << "- **Analyzed extent**: `" << std::dec << fn.analyzedSize << " bytes` | **Complexity V(G)**: `" << fn.complexity << "` | **Incoming XREFs**: `" << fn.xrefCount << "`\n\n";
        ss << "```asm\n" << fn.assemblySummary << "```\n\n";
    }

    return ss.str();
}

} // namespace openreverse
