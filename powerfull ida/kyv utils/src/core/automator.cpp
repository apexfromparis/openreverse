// ============================================================================
// KYV - Core: Automator / Headless Engine Implementation
// ============================================================================

#include "automator.h"
#include "utils/helpers.h"
#include "utils/logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace kyv {

AutoAnalysisResult Automator::AnalyzeProcess(Application& app, DWORD pid, const std::string& processName)
{
    AutoAnalysisResult res;
    res.targetPid = pid;
    res.targetProcessName = processName;

    if (!app.AttachToProcess(pid))
    {
        Logger::Get().Log(LogLevel::Error, "Automator failed to attach to PID %d", pid);
        return res;
    }

    res.success = true;
    res.targetProcessName = app.attachedProcessName;

    auto* mod = app.moduleManager.FindModuleByAddress(app.currentAddress);
    if (!mod && !app.moduleManager.GetModules().empty())
        mod = const_cast<ModuleInfo*>(&app.moduleManager.GetModules()[0]);

    if (!mod)
        return res;

    res.baseAddress = mod->baseAddress;

    // Limit scan size to 8 MB
    size_t scanSize = mod->size;
    if (scanSize > 8ULL * 1024 * 1024)
        scanSize = 8ULL * 1024 * 1024;

    std::vector<uint8_t> bytes(scanSize, 0);
    size_t totalRead = 0;
    for (size_t offset = 0; offset < scanSize; offset += 4096)
    {
        size_t chunk = std::min((size_t)4096, scanSize - offset);
        SIZE_T read = 0;
        if (ReadProcessMemory(app.processHandle, (LPCVOID)(mod->baseAddress + offset), &bytes[offset], chunk, &read))
        {
            totalRead += read;
        }
    }
    if (totalRead == 0)
    {
        res.success = false;
        return res;
    }

    // 1. Scan Strings
    auto stringResults = app.stringScanner.Scan(app.processHandle, mod->baseAddress, mod->baseAddress + scanSize, 4, true, true, 2000);
    res.stringsFound = stringResults.size();
    for (const auto& sr : stringResults)
    {
        if (sr.category == "URL / C2")
            res.c2Urls.push_back(sr.value);
        else if (sr.category == "Registry")
            res.registryKeys.push_back(sr.value);
    }

    // 2. Discover & Decompile Functions
    auto functions = app.functionAnalyzer.DiscoverFunctions(bytes.data(), bytes.size(), mod->baseAddress, app.is64Bit, 200);
    res.functionsDiscovered = functions.size();

    // 3. Scan XREFs
    app.xrefScanner.ScanBuffer(bytes.data(), bytes.size(), mod->baseAddress, mod->name, app.disassembler, app.is64Bit);
    res.totalXrefs = app.xrefScanner.GetTotalXRefsCount();

    // 4. Select interesting functions (e.g., higher complexity or top functions)
    size_t maxReportFuncs = 15;
    for (size_t i = 0; i < functions.size() && res.keyFunctions.size() < maxReportFuncs; ++i)
    {
        auto fi = app.functionAnalyzer.AnalyzeFunction(bytes.data(), bytes.size(),
                                                       functions[i].startAddress, mod->baseAddress,
                                                       app.disassembler, app.is64Bit, 4096);

        // Include if it has complexity >= 2 or if it's among the first 5 functions
        if (fi.cyclomaticComplexity >= 2 || i < 5)
        {
            AutoAnalysisResult::FunctionSummary fs;
            fs.address = fi.startAddress;
            fs.name = fi.name;
            fs.size = fi.size;
            fs.complexity = fi.cyclomaticComplexity;
            auto xrefs = app.xrefScanner.FindXRefsTo(fi.startAddress);
            fs.xrefCount = (int)xrefs.size();
            fs.pseudocode = app.functionAnalyzer.GeneratePseudocode(fi, app.is64Bit);
            res.keyFunctions.push_back(fs);
        }
    }

    return res;
}

std::string Automator::FormatReport(const AutoAnalysisResult& res)
{
    std::ostringstream ss;
    ss << "# KYV Automated Decompilation & Reverse Engineering Report\n\n";
    ss << "- **Target Process**: `" << res.targetProcessName << "` (PID: `" << res.targetPid << "`)\n";
    ss << "- **Base Address**: `0x" << std::uppercase << std::hex << res.baseAddress << "`\n";
    ss << "- **Functions Discovered**: `" << std::dec << res.functionsDiscovered << "`\n";
    ss << "- **Cross-References (XREFs)**: `" << res.totalXrefs << "`\n";
    ss << "- **Strings Discovered**: `" << res.stringsFound << "`\n\n";

    if (!res.c2Urls.empty())
    {
        ss << "## [ALERT] Command & Control (C2) URLs Detected\n";
        for (const auto& url : res.c2Urls)
            ss << "- `" << url << "`\n";
        ss << "\n";
    }

    if (!res.registryKeys.empty())
    {
        ss << "## [ALERT] Sensitive Registry Paths Detected\n";
        for (const auto& reg : res.registryKeys)
            ss << "- `" << reg << "`\n";
        ss << "\n";
    }

    ss << "## Decompiled Hex-Rays C Pseudocode (Key Functions)\n\n";
    for (const auto& fn : res.keyFunctions)
    {
        ss << "### Function `" << fn.name << "` (0x" << std::uppercase << std::hex << fn.address << ")\n";
        ss << "- **Size**: `" << std::dec << fn.size << " bytes` | **Complexity V(G)**: `" << fn.complexity << "` | **Incoming XREFs**: `" << fn.xrefCount << "`\n\n";
        ss << "```c\n" << fn.pseudocode << "```\n\n";
    }

    return ss.str();
}

} // namespace kyv
