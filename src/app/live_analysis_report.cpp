#include "live_analysis_report.h"
#include "app/application.h"
#include "analysis/module_analysis.h"
#include "utils/logger.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <utility>

namespace openreverse {

LiveAnalysisReport LiveAnalysisReporter::BuildForProcess(
    Application& app, DWORD pid, const std::string& processName) const
{
    LiveAnalysisReport report;
    report.targetPid = pid;
    report.targetProcessName = processName;

    if ((!app.isAttached || app.attachedPID != pid || !app.processHandle) && !app.AttachToProcess(pid))
    {
        Logger::Get().Log(LogLevel::Error, "Live report failed to attach to PID %d", pid);
        return report;
    }

    report.targetProcessName = app.attachedProcessName;

    const ModuleInfo* module = app.moduleCatalog.FindModuleByAddress(app.currentAddress);
    if (!module && !app.moduleCatalog.GetModules().empty())
        module = &app.moduleCatalog.GetModules().front();

    if (!module)
        return report;

    report.baseAddress = module->baseAddress;

    ModuleAnalysisOptions options;
    options.maxFunctions = 200;
    options.maxStrings = 2000;
    ModuleAnalysisPipeline analysisPipeline;
    const auto analysis = analysisPipeline.AnalyzeLive(
        app.processHandle, *module, app.is64Bit, options);
    if (!analysis.success)
    {
        Logger::Get().Log(LogLevel::Error, "Live report failed to analyze %s: %s",
                          module->name.c_str(), analysis.error.c_str());
        return report;
    }

    Disassembler disassembler;
    if (!disassembler.Init(app.is64Bit))
        return report;

    report.stringsFound = analysis.strings.size();
    for (const auto& stringResult : analysis.strings)
    {
        if (stringResult.category == "URL")
            report.urls.push_back(stringResult.value);
        else if (stringResult.category == "Registry Path")
            report.registryPaths.push_back(stringResult.value);
    }

    report.functionsDiscovered = analysis.functions.size();
    report.totalXrefs = analysis.xrefs.size();

    constexpr size_t kMaxReportFunctions = 15;
    for (size_t index = 0;
         index < analysis.functions.size() && report.keyFunctions.size() < kMaxReportFunctions;
         ++index)
    {
        const auto& function = analysis.functions[index];
        const auto readResult = app.memoryReader.ReadReadableBlocks(
            app.processHandle, function.startAddress, 4096, 4096);
        if (readResult.blocks.empty() || readResult.blocks.front().baseAddress != function.startAddress)
            continue;
        auto analyzedFunction = functions::AnalyzeFunction(
            readResult.blocks.front().bytes.data(), readResult.blocks.front().bytes.size(),
            function.startAddress, function.startAddress,
            disassembler, app.is64Bit, 4096);
        if (!function.name.empty())
            analyzedFunction.name = function.name;

        if (analyzedFunction.cyclomaticComplexity >= 2 || index < 5)
        {
            LiveAnalysisReport::FunctionSummary summary;
            summary.address = analyzedFunction.startAddress;
            summary.name = analyzedFunction.name;
            summary.analyzedSize = analyzedFunction.analyzedSize;
            summary.complexity = analyzedFunction.cyclomaticComplexity;
            summary.xrefCount = static_cast<int>(std::count_if(
                analysis.xrefs.begin(), analysis.xrefs.end(),
                [&analyzedFunction](const XRefEntry& xref) {
                    return xref.toAddress == analyzedFunction.startAddress;
                }));
            summary.assemblySummary = functions::GenerateAssemblySummary(
                analyzedFunction, app.is64Bit);
            report.keyFunctions.push_back(std::move(summary));
        }
    }

    report.success = true;
    return report;
}

std::string LiveAnalysisReporter::FormatMarkdown(const LiveAnalysisReport& report)
{
    std::ostringstream markdown;
    markdown << "# OpenReverse Automated Analysis Report\n\n";
    markdown << "- **Target Process**: `" << report.targetProcessName << "` (PID: `"
             << report.targetPid << "`)\n";
    markdown << "- **Base Address**: `0x" << std::uppercase << std::hex
             << report.baseAddress << "`\n";
    markdown << "- **Functions Discovered**: `" << std::dec << report.functionsDiscovered << "`\n";
    markdown << "- **Cross-References (XREFs)**: `" << report.totalXrefs << "`\n";
    markdown << "- **Strings Discovered**: `" << report.stringsFound << "`\n\n";

    if (!report.urls.empty())
    {
        markdown << "## Observed URLs\n";
        for (const auto& url : report.urls)
            markdown << "- `" << url << "`\n";
        markdown << "\n";
    }

    if (!report.registryPaths.empty())
    {
        markdown << "## Observed Registry Paths\n";
        for (const auto& registryPath : report.registryPaths)
            markdown << "- `" << registryPath << "`\n";
        markdown << "\n";
    }

    markdown << "## Decoded control-flow evidence (key functions)\n\n";
    for (const auto& function : report.keyFunctions)
    {
        markdown << "### Function `" << function.name << "` (0x" << std::uppercase << std::hex
                 << function.address << ")\n";
        markdown << "- **Analyzed extent**: `" << std::dec << function.analyzedSize
                 << " bytes` | **Complexity V(G)**: `" << function.complexity
                 << "` | **Incoming XREFs**: `" << function.xrefCount << "`\n\n";
        markdown << "```asm\n" << function.assemblySummary << "```\n\n";
    }

    return markdown.str();
}

} // namespace openreverse
