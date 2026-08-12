#include "cli_repl.h"
#include "openreverse_version.h"
#include "app/automator.h"
#include "utils/helpers.h"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <conio.h>
#include <limits>
#include <utility>

namespace openreverse {

namespace {

std::vector<std::string> TokenizeCommand(const std::string& line)
{
    std::vector<std::string> tokens;
    std::string token;
    bool quoted = false;
    for (char character : line)
    {
        if (character == '"')
        {
            quoted = !quoted;
            continue;
        }
        if (!quoted && (character == ' ' || character == '\t'))
        {
            if (!token.empty())
            {
                tokens.push_back(std::move(token));
                token.clear();
            }
            continue;
        }
        token.push_back(character);
    }
    if (!token.empty()) tokens.push_back(std::move(token));
    return tokens;
}

} // namespace

CLIRepl::CLIRepl()
{
    EnableAnsiColors();
    sessions_.push_back({1, "default-session", "", 0, 0, 0, {}});
}

CLIRepl::~CLIRepl() = default;

void CLIRepl::EnableAnsiColors()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hOut == nullptr) return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

void CLIRepl::PrintBanner()
{
    std::cout << "█▀▀█ █▀▀█ █▀▀█ █▀▀▄ █▀▀▄ █▀▀▀ █  █ █▀▀▀ █▀▀▄ █▀▀▀ █▀▀▀\n";
    std::cout << "█  █ █  █ █▀▀▀ █  █ █▀▀▄ █▀▀  ▀▄▄▀ █▀▀  █▀▀▄ ▀▀▀█ █▀▀ \n";
    std::cout << "▀▀▀▀ █▀▀▀ ▀▀▀▀ ▀  ▀ ▀  ▀ ▀▀▀▀  ▀▀  ▀▀▀▀ ▀  ▀ ▀▀▀▀ ▀▀▀▀\n\n";
    std::cout << "openreverse tui | reverse engineering shell\n";
    std::cout << "Type '/' for commands (/help, /open, /sessions...) or type directly to chat.\n\n";
}

void CLIRepl::PrintCLIVersion()
{
    std::cout << openreverse::kVersion << " (openreverse)\n";
}

void CLIRepl::PrintCLIHelp()
{
    std::cout << "█▀▀█ █▀▀█ █▀▀█ █▀▀▄ █▀▀▄ █▀▀▀ █  █ █▀▀▀ █▀▀▄ █▀▀▀ █▀▀▀\n";
    std::cout << "█  █ █  █ █▀▀▀ █  █ █▀▀▄ █▀▀  ▀▄▄▀ █▀▀  █▀▀▄ ▀▀▀█ █▀▀ \n";
    std::cout << "▀▀▀▀ █▀▀▀ ▀▀▀▀ ▀  ▀ ▀  ▀ ▀▀▀▀  ▀▀  ▀▀▀▀ ▀  ▀ ▀▀▀▀ ▀▀▀▀\n\n";
    std::cout << "Commands:\n";
    std::cout << "  openreverse [binary]            start the GUI and optionally open a binary\n";
    std::cout << "  openreverse --cli               start the interactive command shell\n";
    std::cout << "  openreverse attach <pid>        attach to a running target or PID\n";
    std::cout << "  openreverse dump <file>         analyze a mapped PE image or minidump statically\n";
    std::cout << "    --base <va> --size <bytes> --arch <x86|x64>  required for raw snapshots\n";
    std::cout << "    --module <va>                 select a module from a multi-module minidump\n";
    std::cout << "  openreverse run [message..]     run openreverse with a message / prompt\n";
    std::cout << "  openreverse providers           manage AI providers and credentials [aliases: auth]\n";
    std::cout << "  openreverse models              show the currently configured model\n";
    std::cout << "  openreverse stats               show local session configuration\n";
    std::cout << "  openreverse session             manage sessions\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help          show help                                                            [boolean]\n";
    std::cout << "  -v, --version       show version number                                                  [boolean]\n\n";
}

void CLIRepl::PrintHelp()
{
    std::cout << "OPENREVERSE Terminal Interactive Commands:\n";
    std::cout << "  open <path.exe>       Open a binary and run OpenReverse analysis\n";
    std::cout << "  attach <PID>          Attach to a PID and run OpenReverse analysis\n";
    std::cout << "  functions [filter]    List discovered functions (Addr, Name, Size, V(G), XREFs)\n";
    std::cout << "  decompile <addr|name> Show decoded instructions grouped by basic block\n";
    std::cout << "  cfg <addr|name>       Display basic block control flow graph & branching\n";
    std::cout << "  xrefs <addr|name>     Show Cross-References (CALL, JUMP, READ, WRITE) to/from addr\n";
    std::cout << "  strings [filter]      Display strings with neutral evidence categories\n";
    std::cout << "  disasm <addr> [cnt]   Disassemble hex instructions at memory address\n";
    std::cout << "  modules               List loaded PE modules and base addresses\n";
    std::cout << "  report [file.md]      Export an analysis report to disk\n";
    std::cout << "---------------------------------------------------------------------------------\n";
    std::cout << "AI Copilot & Model Commands:\n";
    std::cout << "  ai-connect [prov] [key]  Configure a compatible provider (openai, gemini, groq, ollama)\n";
    std::cout << "  ai-setup / connect       Alias for interactive AI setup wizard\n";
    std::cout << "  ai-config <prov> <url> <mod> Configure AI manually (e.g. OpenAI-compatible https://api.openai.com/v1 gpt-4o)\n";
    std::cout << "  ai-key <api_key>      Set and securely store AI API Key\n";
    std::cout << "  ai-model <model_name> Change active AI model (e.g. gpt-4o, qwen2.5-coder:7b)\n";
    std::cout << "  ai-status             Display current AI connection status and configuration\n";
    std::cout << "  ai-ask <question>     Ask AI Copilot any reverse engineering question\n";
    std::cout << "  ai-explain <func>     Ask AI to review decoded function evidence\n";
    std::cout << "  ai-rename <func>      Ask AI to suggest meaningful variable & function names\n";
    std::cout << "  ai-vuln <func>        Ask AI to audit decoded function evidence\n";
    std::cout << "---------------------------------------------------------------------------------\n";
    std::cout << "  gui                   Switch immediately to Graphical User Interface\n";
    std::cout << "  exit / quit           Exit OpenReverse\n\n";
}

uint64_t CLIRepl::ParseAddressOrName(Application& app, const std::string& token)
{
    if (token.empty()) return 0;
    if (token.front() == '-' || token.front() == '+') return 0;
    for (const auto& fn : app.analysisPanel.GetFunctions())
    {
        if (helpers::ToLower(fn.name) == helpers::ToLower(token) ||
            fn.name.find(token) != std::string::npos)
        {
            return fn.startAddress;
        }
    }
    try
    {
        size_t parsed = 0;
        const uint64_t address = std::stoull(token, &parsed, 16);
        return parsed == token.size() ? address : 0;
    }
    catch (...)
    {
        return 0;
    }
}

void CLIRepl::HandleAttach(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "\033[1;31mUsage: attach <PID>\033[0m\n";
        return;
    }
    DWORD pid = 0;
    try
    {
        if (args[1].empty() || args[1].front() == '-' || args[1].front() == '+')
            throw std::invalid_argument("PID");
        size_t parsed = 0;
        const unsigned long value = std::stoul(args[1], &parsed, 10);
        if (parsed != args[1].size() || value == 0 || value > (std::numeric_limits<DWORD>::max)())
            throw std::out_of_range("PID");
        pid = static_cast<DWORD>(value);
    }
    catch (...)
    {
        std::cout << "\033[1;31mInvalid PID: " << args[1] << "\033[0m\n";
        return;
    }
    std::cout << "[*] Attaching to PID " << pid << " and starting analysis...\n";
    if (!app.AttachToProcess(pid))
    {
        std::cout << "\033[1;31m[-] Failed to attach to PID " << pid << "\033[0m\n";
        return;
    }
    app.analysisPanel.AnalyzeCurrentModule(app);
    if (app.analysisDatabase.GetModules().empty())
    {
        std::cout << "\033[1;31m[-] Failed to analyze PID " << pid << "\033[0m\n";
        app.DetachFromProcess();
        return;
    }
    const auto& analysis = app.analysisDatabase.GetModules().begin()->second;
    std::cout << "\033[1;32m[+] Attached to " << app.attachedProcessName << " (0x" << std::hex
              << analysis.module.baseAddress << ")\033[0m\n";
    std::cout << "[+] Functions: \033[1;36m" << std::dec << analysis.functions.size()
              << "\033[0m | XREFs: \033[1;36m" << analysis.xrefs.size()
              << "\033[0m | Strings: \033[1;36m" << analysis.strings.size() << "\033[0m\n\n";
}

bool CLIRepl::HandleOpen(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "\033[1;31mUsage: open <executable_path>\033[0m\n";
        return false;
    }
    std::string exePath = args[1];

    if (GetFileAttributesA(exePath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        std::cout << "\033[1;31m[-] File does not exist: '" << exePath << "'\033[0m\n";
        return false;
    }

    std::cout << "[*] Analyzing PE binary offline: '" << exePath << "'...\n";
    if (app.OpenBinaryFile(exePath))
    {
        uint64_t baseAddr = app.moduleManager.GetModules().empty() ? 0 : app.moduleManager.GetModules()[0].baseAddress;
        std::cout << "\033[1;32m[+] Successfully parsed offline target: " << app.attachedProcessName << " (" << (app.is64Bit ? "x64" : "x86") << ")\033[0m\n";
        std::cout << "[+] Base Address: \033[1;36m0x" << std::hex << baseAddr << "\033[0m\n";
        std::cout << "[+] Functions Discovered: \033[1;36m" << std::dec << app.analysisPanel.GetFunctions().size() << "\033[0m | Strings: \033[1;36m" << app.stringResults.size() << "\033[0m\n\n";
        return true;
    }

    std::cout << "\033[1;31m[-] Failed to parse PE binary: '" << exePath << "'. The file was not executed.\033[0m\n";
    return false;
}

void CLIRepl::HandleFunctions(Application& app, const std::vector<std::string>& args)
{
    auto functions = app.analysisPanel.GetFunctions();
    if (functions.empty())
    {
        std::cout << "No functions discovered. Run 'open <exe>' or 'attach <pid>' first.\n";
        return;
    }
    std::string filter = (args.size() > 1) ? helpers::ToLower(args[1]) : "";
    std::cout << "\n\033[1;37mAddress            Name                         Size    Blocks  V(G)  XREFs\033[0m\n";
    std::cout << "----------------------------------------------------------------------------\n";
    int count = 0;
    for (const auto& fn : functions)
    {
        if (!filter.empty() && helpers::ToLower(fn.name).find(filter) == std::string::npos)
            continue;

        std::string addrStr = helpers::FormatAddress(fn.startAddress, app.is64Bit);
        std::ostringstream sizeText;
        if (fn.boundaryKnown) sizeText << std::dec << fn.size << " B";
        else sizeText << "?";
        std::cout << "\033[1;36m" << addrStr << "\033[0m  "
                  << std::left << std::setw(28) << fn.name
                  << std::right << std::setw(7) << sizeText.str() << "  "
                  << std::setw(6) << fn.cfg.basicBlocks.size() << "  ";

        if (fn.cfg.basicBlocks.empty())
            std::cout << std::setw(4) << "?" << "  ";
        else if (fn.cyclomaticComplexity >= 10)
            std::cout << "\033[1;31m" << std::setw(4) << fn.cyclomaticComplexity << "\033[0m  ";
        else
            std::cout << "\033[1;32m" << std::setw(4) << fn.cyclomaticComplexity << "\033[0m  ";

        std::cout << std::setw(5) << fn.xrefCount << "\n";
        if (++count >= 30)
        {
            std::cout << "... (" << functions.size() - count << " more functions. Use filter to narrow search)\n";
            break;
        }
    }
    std::cout << "\n";
}

void CLIRepl::HandleDecompile(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "\033[1;31mUsage: decompile <address_or_function_name>\033[0m\n";
        return;
    }
    uint64_t addr = ParseAddressOrName(app, args[1]);
    if (addr == 0)
    {
        std::cout << "\033[1;31m[-] Could not find function: " << args[1] << "\033[0m\n";
        return;
    }
    auto bytes = app.memoryReader.ReadBytes(app.processHandle, addr, 4096);
    if (bytes.empty())
    {
        std::cout << "\033[1;31m[-] Could not read memory at 0x" << std::hex << addr << "\033[0m\n";
        return;
    }

    auto fi = app.functionAnalyzer.AnalyzeFunction(bytes.data(), bytes.size(), addr, addr, app.disassembler, app.is64Bit, 4096);
    const std::string summary = app.functionAnalyzer.GenerateAssemblySummary(fi, app.is64Bit);
    std::cout << "\n\033[1;36m" << summary << "\033[0m\n";
}

void CLIRepl::HandleCFG(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "\033[1;31mUsage: cfg <address_or_function_name>\033[0m\n";
        return;
    }
    uint64_t addr = ParseAddressOrName(app, args[1]);
    if (addr == 0) return;

    auto bytes = app.memoryReader.ReadBytes(app.processHandle, addr, 4096);
    auto fi = app.functionAnalyzer.AnalyzeFunction(bytes.data(), bytes.size(), addr, addr, app.disassembler, app.is64Bit, 4096);

    std::cout << "\n\033[1;33m[CFG] Control Flow Graph Basic Blocks for " << fi.name << " (V(G)=" << fi.cyclomaticComplexity << "):\033[0m\n";
    for (size_t i = 0; i < fi.cfg.basicBlocks.size(); ++i)
    {
        const auto& bb = fi.cfg.basicBlocks[i];
        std::cout << "  Block " << i << ": [" << helpers::FormatAddress(bb.startAddress, app.is64Bit)
                  << " -> " << helpers::FormatAddress(bb.endAddress, app.is64Bit) << "] ("
                  << bb.instructions.size() << " instructions)\n";
        if (bb.branchAddr != 0)
            std::cout << "      |-- Branch Target: " << helpers::FormatAddress(bb.branchAddr, app.is64Bit) << "\n";
        if (bb.fallthroughAddr != 0)
            std::cout << "      |-- Fallthrough:   " << helpers::FormatAddress(bb.fallthroughAddr, app.is64Bit) << "\n";
    }
    std::cout << "\n";
}

void CLIRepl::HandleXRefs(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "\033[1;31mUsage: xrefs <address_or_function_name>\033[0m\n";
        return;
    }
    uint64_t addr = ParseAddressOrName(app, args[1]);
    if (addr == 0) return;

    auto xrefsTo = app.xrefScanner.FindXRefsTo(addr);
    std::cout << "\n\033[1;32m[XREFs UP (To)] References calling/targeting " << helpers::FormatAddress(addr, app.is64Bit) << ": (" << xrefsTo.size() << ")\033[0m\n";
    for (const auto& xr : xrefsTo)
    {
        const char* typeStr = "READ";
        switch (xr.type)
        {
        case XRefType::Call: typeStr = "CALL"; break;
        case XRefType::Jump: typeStr = "JUMP"; break;
        case XRefType::Write: typeStr = "WRITE"; break;
        case XRefType::ReadWrite: typeStr = "R/W"; break;
        case XRefType::Address: typeStr = "ADDRESS"; break;
        case XRefType::String: typeStr = "STRING"; break;
        case XRefType::Import: typeStr = "IMPORT"; break;
        case XRefType::Global: typeStr = "GLOBAL"; break;
        case XRefType::Data: typeStr = "DATA"; break;
        default: break;
        }
        std::cout << "  [" << typeStr << "] From: \033[1;36m" << helpers::FormatAddress(xr.fromAddress, app.is64Bit) << "\033[0m -> " << xr.instructionText << "\n";
    }
    std::cout << "\n";
}

void CLIRepl::HandleStrings(Application& app, const std::vector<std::string>& args)
{
    std::string filter = (args.size() > 1) ? helpers::ToLower(args[1]) : "";
    auto* mod = app.moduleManager.FindModuleByAddress(app.currentAddress);
    if (!mod && !app.moduleManager.GetModules().empty())
        mod = const_cast<ModuleInfo*>(&app.moduleManager.GetModules()[0]);
    if (!mod) return;

    std::vector<StringResult> res;
    if (app.attachedPID == 0)
        res = app.stringResults;
    else
        res = app.stringScanner.Scan(app.processHandle, mod->baseAddress,
            mod->baseAddress + std::min((size_t)mod->size, (size_t)8192000), 4, true, true, 2000);
    std::cout << "\n\033[1;37mAddress            Category       Value\033[0m\n";
    std::cout << "----------------------------------------------------------------------------\n";
    int count = 0;
    for (const auto& sr : res)
    {
        if (!filter.empty() && helpers::ToLower(sr.value).find(filter) == std::string::npos &&
            helpers::ToLower(sr.category).find(filter) == std::string::npos)
            continue;

        std::string addrStr = helpers::FormatAddress(sr.address, app.is64Bit);
        std::cout << "\033[1;36m" << addrStr << "\033[0m  ";
        std::cout << std::left << std::setw(20) << sr.category << "  ";

        std::cout << sr.value << "\n";
        if (++count >= 30)
        {
            std::cout << "... (" << res.size() - count << " more strings)\n";
            break;
        }
    }
    std::cout << "\n";
}

void CLIRepl::HandleDisasm(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2) return;
    uint64_t addr = ParseAddressOrName(app, args[1]);
    if (addr == 0) return;
    size_t lines = 15;
    if (args.size() > 2)
    {
        try
        {
            if (args[2].empty() || args[2].front() == '-' || args[2].front() == '+')
                throw std::invalid_argument("instruction count");
            size_t parsed = 0;
            lines = std::stoull(args[2], &parsed, 10);
            if (parsed != args[2].size() || lines == 0 || lines > 4096)
                throw std::out_of_range("line count");
        }
        catch (...)
        {
            std::cout << "\033[1;31mInvalid instruction count: " << args[2] << "\033[0m\n";
            return;
        }
    }

    auto bytes = app.memoryReader.ReadBytes(app.processHandle, addr, lines * 15);
    auto insts = app.disassembler.Disassemble(bytes.data(), bytes.size(), addr, lines);
    std::cout << "\n\033[1;33mDisassembly at " << helpers::FormatAddress(addr, app.is64Bit) << ":\033[0m\n";
    for (const auto& i : insts)
    {
        std::cout << "  \033[1;36m" << helpers::FormatAddress(i.address, app.is64Bit) << "\033[0m  "
                  << std::left << std::setw(20) << helpers::BytesToHex(i.bytes, i.size)
                  << "\033[1;32m" << std::left << std::setw(10) << i.mnemonic << "\033[0m "
                  << i.operands << "\n";
    }
    std::cout << "\n";
}

void CLIRepl::HandleModules(Application& app, const std::vector<std::string>& args)
{
    auto mods = app.moduleManager.GetModules();
    std::cout << "\n\033[1;37mBase Address       Size        Module Name\033[0m\n";
    std::cout << "----------------------------------------------------------------------------\n";
    for (const auto& m : mods)
    {
        std::cout << "\033[1;36m" << helpers::FormatAddress(m.baseAddress, app.is64Bit) << "\033[0m  "
                  << std::left << std::setw(10) << m.size << "  "
                  << m.name << "\n";
    }
    std::cout << "\n";
}

void CLIRepl::HandleReport(Application& app, const std::vector<std::string>& args)
{
    std::string outFile = (args.size() > 1) ? args[1] : "openreverse_interactive_report.md";
    if (!app.isAttached)
    {
        std::cout << "\033[1;31m[-] Could not generate report. Open a binary or attach to a process first.\033[0m\n";
        return;
    }
    AutoAnalysisResult res;
    if (app.isAttached && app.attachedPID == 0)
    {
        res.success = true;
        res.targetProcessName = app.attachedProcessName;
        res.targetPid = 0;
        if (!app.moduleManager.GetModules().empty())
            res.baseAddress = app.moduleManager.GetModules()[0].baseAddress;
        res.functionsDiscovered = app.analysisPanel.GetFunctions().size();
        res.totalXrefs = app.xrefScanner.GetTotalXRefsCount();
        res.stringsFound = app.stringResults.size();
        for (const auto& string : app.stringResults)
        {
            if (string.category == "URL") res.urls.push_back(string.value);
            if (string.category == "Registry Path") res.registryPaths.push_back(string.value);
        }
        for (const auto& function : app.analysisPanel.GetFunctions())
        {
            if (res.keyFunctions.size() >= 15) break;
            auto bytes = app.memoryReader.ReadBytes(nullptr, function.startAddress, 4096);
            auto analyzed = app.functionAnalyzer.AnalyzeFunction(bytes.data(), bytes.size(),
                function.startAddress, function.startAddress, app.disassembler, app.is64Bit, 4096);
            if (!function.name.empty()) analyzed.name = function.name;
            AutoAnalysisResult::FunctionSummary summary;
            summary.address = analyzed.startAddress;
            summary.name = analyzed.name;
            summary.analyzedSize = analyzed.analyzedSize;
            summary.complexity = analyzed.cyclomaticComplexity;
            summary.xrefCount = static_cast<int>(app.xrefScanner.FindXRefsTo(analyzed.startAddress).size());
            summary.assemblySummary = app.functionAnalyzer.GenerateAssemblySummary(analyzed, app.is64Bit);
            res.keyFunctions.push_back(std::move(summary));
        }
    }
    else
    {
        Automator automator;
        res = automator.AnalyzeProcess(app, app.attachedPID, app.attachedProcessName);
    }
    if (res.success)
    {
        std::string rep = Automator::FormatReport(res);
        std::ofstream ofs(outFile);
        ofs << rep;
        ofs.close();
        std::cout << "\033[1;32m[+] Complete Markdown report exported to: " << outFile << "\033[0m\n\n";
    }
    else
    {
        std::cout << "\033[1;31m[-] Could not generate report. Make sure a process is attached.\033[0m\n";
    }
}

void CLIRepl::HandleAIConnect(Application& app, const std::vector<std::string>& args)
{
    std::string provider = "Ollama";
    std::string baseUrl = "http://localhost:11434/v1";
    std::string model = "qwen2.5-coder:7b";
    std::string apiKey;

    if (args.size() >= 2)
    {
        std::string provInput = helpers::ToLower(args[1]);
        if (provInput == "ollama" || provInput == "local" || provInput == "1")
        {
            provider = "Ollama";
            baseUrl = "http://localhost:11434/v1";
            model = (args.size() >= 3) ? args[2] : "qwen2.5-coder:7b";
        }
        else if (provInput == "lmstudio" || provInput == "lms" || provInput == "lm-studio" || provInput == "2")
        {
            provider = "LM Studio";
            baseUrl = "http://localhost:1234/v1";
            model = (args.size() >= 3) ? args[2] : "qwen2.5-coder-7b-instruct";
        }
        else if (provInput == "qwen" || provInput == "qwencoder" || provInput == "qwen-coder")
        {
            provider = "Ollama";
            baseUrl = "http://localhost:11434/v1";
            model = "qwen2.5-coder:7b";
        }
        else if (provInput == "deepseek" || provInput == "deepseek-coder" || provInput == "deepseek-r1")
        {
            provider = "Ollama";
            baseUrl = "http://localhost:11434/v1";
            model = "deepseek-coder-v2";
        }
        else if (provInput == "llama" || provInput == "llama3" || provInput == "llama-3")
        {
            provider = "Ollama";
            baseUrl = "http://localhost:11434/v1";
            model = "llama3.1:8b";
        }
        else if (provInput == "groq" || provInput == "3")
        {
            provider = "Groq Cloud";
            baseUrl = "https://api.groq.com/openai/v1";
            model = (args.size() >= 4) ? args[3] : "llama-3.3-70b-versatile";
            if (args.size() >= 3) apiKey = args[2];
        }
        else if (provInput == "openrouter" || provInput == "4")
        {
            provider = "OpenRouter";
            baseUrl = "https://openrouter.ai/api/v1";
            model = (args.size() >= 4) ? args[3] : "qwen/qwen-2.5-coder-32b-instruct";
            if (args.size() >= 3) apiKey = args[2];
        }
        else if (provInput == "openai" || provInput == "5" || provInput == "gpt")
        {
            provider = "OpenAI";
            baseUrl = "https://api.openai.com/v1";
            model = (args.size() >= 4) ? args[3] : "gpt-4o";
            if (args.size() >= 3) apiKey = args[2];
        }
        else if (provInput == "gemini" || provInput == "google" || provInput == "6")
        {
            provider = "Google Gemini";
            baseUrl = "https://generativelanguage.googleapis.com/v1beta/openai/";
            model = (args.size() >= 4) ? args[3] : "gemini-2.0-flash";
            if (args.size() >= 3) apiKey = args[2];
        }
        else if (provInput == "mistral" || provInput == "7")
        {
            provider = "Mistral AI";
            baseUrl = "https://api.mistral.ai/v1";
            model = (args.size() >= 4) ? args[3] : "codestral-latest";
            if (args.size() >= 3) apiKey = args[2];
        }
        else
        {
            std::cout << "\033[1;31m[-] Unknown AI provider: " << args[1] << "\033[0m\n";
            std::cout << "Available presets: ollama, lmstudio, qwen, deepseek, llama, groq, openrouter, openai, gemini, mistral\n";
            std::cout << "Or type '/connect' without arguments for the interactive setup wizard.\n";
            return;
        }
    }
    else
    {
        std::cout << "\n\033[1;36m=================================================================================\033[0m\n";
        std::cout << "\033[1;36m                  OPENREVERSE AI COPILOT - QUICK CONNECT WIZARD                  \033[0m\n";
        std::cout << "\033[1;36m=================================================================================\033[0m\n";
        std::cout << "Select your AI provider:\n";
        std::cout << "  \033[1;32m1)\033[0m Ollama         (local OpenAI-compatible endpoint)\n";
        std::cout << "  \033[1;32m2)\033[0m LM Studio      (local OpenAI-compatible endpoint)\n";
        std::cout << "  \033[1;32m3)\033[0m Groq Cloud\n";
        std::cout << "  \033[1;32m4)\033[0m OpenRouter\n";
        std::cout << "  \033[1;32m5)\033[0m OpenAI         (GPT-4o, GPT-4o-mini, o1, o3-mini)\n";
        std::cout << "  \033[1;32m6)\033[0m Google Gemini  (OpenAI-compatible endpoint)\n";
        std::cout << "  \033[1;32m7)\033[0m Mistral AI\n";
        std::cout << "  \033[1;32m8)\033[0m Custom         (OpenAI-compatible API server)\n";
        std::cout << "\033[1;36m---------------------------------------------------------------------------------\033[0m\n";
        std::cout << "Enter provider [1-8] (default 1 - Ollama): ";

        std::string choiceLine;
        std::getline(std::cin, choiceLine);
        int choice = 1;
        if (!choiceLine.empty()) choice = atoi(choiceLine.c_str());
        if (choice < 1 || choice > 8) choice = 1;

        if (choice == 1)      { provider = "Ollama";                 baseUrl = "http://localhost:11434/v1";                              model = "qwen2.5-coder:7b"; }
        else if (choice == 2) { provider = "LM Studio";              baseUrl = "http://localhost:1234/v1";                               model = "qwen2.5-coder-7b-instruct"; }
        else if (choice == 3) { provider = "Groq Cloud";             baseUrl = "https://api.groq.com/openai/v1";                         model = "llama-3.3-70b-versatile"; }
        else if (choice == 4) { provider = "OpenRouter";             baseUrl = "https://openrouter.ai/api/v1";                           model = "qwen/qwen-2.5-coder-32b-instruct"; }
        else if (choice == 5) { provider = "OpenAI";                 baseUrl = "https://api.openai.com/v1";                              model = "gpt-4o"; }
        else if (choice == 6) { provider = "Google Gemini";          baseUrl = "https://generativelanguage.googleapis.com/v1beta/openai/"; model = "gemini-2.0-flash"; }
        else if (choice == 7) { provider = "Mistral AI";             baseUrl = "https://api.mistral.ai/v1";                              model = "codestral-latest"; }
        else if (choice == 8) {
            std::cout << "Enter Custom Provider Name [default Custom]: ";
            std::string provInput;
            std::getline(std::cin, provInput);
            provider = provInput.empty() ? "Custom" : provInput;

            std::cout << "Enter Base URL [default http://localhost:8000/v1]: ";
            std::string urlInput;
            std::getline(std::cin, urlInput);
            baseUrl = urlInput.empty() ? "http://localhost:8000/v1" : urlInput;

            model = "gpt-4o";
        }

        if (choice == 1 || choice == 2)
        {
            std::cout << "\033[1;36m---------------------------------------------------------------------------------\033[0m\n";
            std::cout << "Select local model:\n";
            std::cout << "  \033[1;32m1)\033[0m Qwen-2.5-Coder:7b   (Recommended default for x86/x64 Reverse Engineering)\n";
            std::cout << "  \033[1;32m2)\033[0m DeepSeek-Coder-v2   (Strong reasoning & disassembly understanding)\n";
            std::cout << "  \033[1;32m3)\033[0m Llama-3.1:8b        (General versatile coding & analysis)\n";
            std::cout << "Enter model choice [1-3] (default 1): ";
            std::string mChoice;
            std::getline(std::cin, mChoice);
            int mc = atoi(mChoice.c_str());
            if (mc == 2) model = "deepseek-coder-v2";
            else if (mc == 3) model = "llama3.1:8b";
            else model = (choice == 1) ? "qwen2.5-coder:7b" : "qwen2.5-coder-7b-instruct";

        }
        else
        {
            std::cout << "Enter API Key (stored securely in Windows Credential Manager): ";
            std::getline(std::cin, apiKey);

            std::cout << "Enter Model Name [default " << model << "]: ";
            std::string modelInput;
            std::getline(std::cin, modelInput);
            if (!modelInput.empty())
            {
                modelInput.erase(0, modelInput.find_first_not_of(" \t\r\n"));
                modelInput.erase(modelInput.find_last_not_of(" \t\r\n") + 1);
                if (!modelInput.empty())
                    model = modelInput;
            }
        }
    }

    app.aiService.Configure(provider, baseUrl, model);

    if (!apiKey.empty())
    {
        if (app.aiService.SaveApiKey(apiKey))
        {
            std::cout << "\033[1;32m[+] API Key saved securely to Windows Credential Manager.\033[0m\n";
        }
        else
        {
            std::cout << "\033[1;33m[!] Warning: Could not save API Key to Windows Credential Manager.\033[0m\n";
        }
    }
    std::cout << "\n\033[1;32m=================================================================================\033[0m\n";
    std::cout << "\033[1;32m[+] AI provider configured\033[0m\n";
    std::cout << "    Provider   : \033[1;36m" << app.aiService.Provider() << "\033[0m\n";
    std::cout << "    Base URL   : \033[1;36m" << app.aiService.BaseUrl() << "\033[0m\n";
    std::cout << "    Model      : \033[1;36m" << app.aiService.Model() << "\033[0m\n";
    std::cout << "    Key Status : \033[1;36m"
              << (!app.aiService.RequiresApiKey() ? "Not required for loopback" :
                  (app.aiService.HasSavedApiKey() ? "Saved in Credential Manager" : "Not saved"))
              << "\033[0m\n";
    std::cout << "\033[1;32m=================================================================================\033[0m\n";
    std::cout << "Tip: Type \033[1;33mai-ask What is this binary doing?\033[0m or \033[1;33mai-explain <func_addr>\033[0m\n\n";
}

void CLIRepl::HandleAIConfig(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 4)
    {
        std::cout << "Usage: ai-config <provider> <url> <model>\n";
        std::cout << "Example: ai-config OpenAI-compatible https://api.openai.com/v1 gpt-4o\n";
        return;
    }
    app.aiService.Configure(args[1], args[2], args[3]);
    std::cout << "[+] AI Copilot configured -> Provider: " << args[1]
              << " | BaseURL: " << args[2] << " | Model: " << args[3] << "\n";
}

void CLIRepl::HandleAIKey(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "Usage: ai-key <api_key>\n";
        return;
    }
    if (app.aiService.SaveApiKey(args[1]))
    {
        std::cout << "[+] API Key saved securely to Windows Credential Manager.\n";
    }
    else
    {
        std::cout << "[-] Failed to save API Key to Windows Credential Manager.\n";
    }
}

void CLIRepl::HandleAIModel(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "Usage: ai-model <model_name>\n";
        return;
    }
    app.aiService.Configure(app.aiService.Provider(), app.aiService.BaseUrl(), args[1]);
    std::cout << "[+] Switched active AI Model to: " << args[1] << "\n";
}

void CLIRepl::HandleAIStatus(Application& app, const std::vector<std::string>& args)
{
    std::cout << "=== OPENREVERSE AI Copilot Status ===\n";
    std::cout << "  Provider   : " << app.aiService.Provider() << "\n";
    std::cout << "  Base URL   : " << app.aiService.BaseUrl() << "\n";
    std::cout << "  Model      : " << app.aiService.Model() << "\n";
    std::cout << "  API Key    : " << (app.aiService.HasSavedApiKey() ? "[Saved in Windows Credential Manager]" : "[Not Saved - use 'ai-key <key>']") << "\n";
    std::cout << "  Status     : " << app.aiService.Status() << "\n";
    std::cout << "  Messages   : " << app.aiService.Conversation().size() << " in current history\n";
    std::cout << "=====================================\n";
}

void CLIRepl::HandleAIAsk(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "Usage: ai-ask <question...>\n";
        return;
    }
    std::string prompt;
    for (size_t i = 1; i < args.size(); ++i)
    {
        if (i > 1) prompt += " ";
        prompt += args[i];
    }
    std::cout << "[*] Sending request to AI Copilot (" << app.aiService.Model() << ")...\n";
    app.aiService.Send(prompt, app.GetAIContextSummary());

    int timeoutMs = 25000;
    while (app.aiService.State() == openreverse::ai::ChatState::Working && timeoutMs > 0)
    {
        Sleep(100);
        timeoutMs -= 100;
    }

    const auto& conv = app.aiService.Conversation();
    if (!conv.empty() && conv.back().role == "assistant")
    {
        std::cout << "\n=== AI Copilot Response ===\n" << conv.back().content << "\n===========================\n";
    }
    else
    {
        std::cout << "[-] AI Copilot request failed or timed out: " << app.aiService.Status() << "\n";
    }
}

void CLIRepl::HandleAIExplain(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "Usage: ai-explain <addr|name>\n";
        return;
    }
    uint64_t addr = ParseAddressOrName(app, args[1]);
    if (addr == 0)
    {
        std::cout << "[-] Function not found: " << args[1] << "\n";
        return;
    }
    const std::string evidence = AssemblySummaryFor(app, addr);
    std::string prompt = "Review this decoded control-flow and assembly evidence. Separate observations from inferences:\n```asm\n" + evidence + "\n```";

    std::cout << "[*] Explaining function 0x" << std::hex << addr << std::dec << " via AI Copilot...\n";
    app.aiService.Send(prompt, app.GetAIContextSummary());

    int timeoutMs = 25000;
    while (app.aiService.State() == openreverse::ai::ChatState::Working && timeoutMs > 0)
    {
        Sleep(100);
        timeoutMs -= 100;
    }

    const auto& conv = app.aiService.Conversation();
    if (!conv.empty() && conv.back().role == "assistant")
    {
        std::cout << "\n=== AI Function Analysis ===\n" << conv.back().content << "\n============================\n";
    }
    else
    {
        std::cout << "[-] AI Copilot request failed or timed out: " << app.aiService.Status() << "\n";
    }
}

void CLIRepl::HandleAIRename(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "Usage: ai-rename <addr|name>\n";
        return;
    }
    uint64_t addr = ParseAddressOrName(app, args[1]);
    if (addr == 0)
    {
        std::cout << "[-] Function not found: " << args[1] << "\n";
        return;
    }
    const std::string evidence = AssemblySummaryFor(app, addr);
    std::string prompt = "Review this decoded assembly evidence and suggest descriptive names as hypotheses in a markdown table:\n```asm\n" + evidence + "\n```";

    std::cout << "[*] Asking AI Copilot for renaming suggestions for 0x" << std::hex << addr << std::dec << "...\n";
    app.aiService.Send(prompt, app.GetAIContextSummary());

    int timeoutMs = 25000;
    while (app.aiService.State() == openreverse::ai::ChatState::Working && timeoutMs > 0)
    {
        Sleep(100);
        timeoutMs -= 100;
    }

    const auto& conv = app.aiService.Conversation();
    if (!conv.empty() && conv.back().role == "assistant")
    {
        std::cout << "\n=== AI Renaming Suggestions ===\n" << conv.back().content << "\n===============================\n";
    }
    else
    {
        std::cout << "[-] AI Copilot request failed or timed out: " << app.aiService.Status() << "\n";
    }
}

void CLIRepl::HandleAITriage(Application& app, const std::vector<std::string>& args)
{
    (void)args;
    std::cout << "\033[1;36m[*] Generating threat report and MITRE ATT&CK mapping...\033[0m\n";
    std::string exeName = app.attachedProcessName.empty() ? "Target Binary" : app.attachedProcessName;
    size_t fnCount = app.analysisPanel.GetFunctions().size();
    
    std::string prompt = "Review the deterministic analysis context for target: `" + exeName + "` (" + std::to_string(fnCount) + " functions discovered).\n"
                         "Include:\n"
                         "1. **Observed evidence**: only strings, imports, Xrefs, and instructions present in the context.\n"
                         "2. **Hypotheses**: clearly label interpretations and uncertainty.\n"
                         "3. **MITRE ATT&CK candidates**: include a technique only when evidence supports review.\n"
                         "4. **Functions to review**: cite only addresses present in the context.";

    app.aiService.Send(prompt, app.GetAIContextSummary());

    int timeoutMs = 30000;
    while (app.aiService.State() == openreverse::ai::ChatState::Working && timeoutMs > 0)
    {
        Sleep(100);
        timeoutMs -= 100;
    }

    const auto& conv = app.aiService.Conversation();
    if (!conv.empty() && conv.back().role == "assistant")
    {
        std::cout << "\n\033[1;33m=== OPENREVERSE THREAT TRIAGE & MITRE ATT&CK REPORT ===\033[0m\n";
        std::cout << conv.back().content << "\n";
        std::cout << "\033[1;33m==================================================================\033[0m\n\n";
    }
    else
    {
        std::cout << "[-] AI Copilot request failed or timed out: " << app.aiService.Status() << "\n";
    }
}

void CLIRepl::HandleAIAutoRename(Application& app, const std::vector<std::string>& args)
{
    (void)args;
    std::cout << "\033[1;36m[*] Launching Global AI Name & Type Inference across all discovered functions...\033[0m\n";
    auto funcs = app.analysisPanel.GetFunctions();
    if (funcs.empty()) {
        std::cout << "[-] No functions discovered in current target. Open a binary (/open) or attach (/attach) first.\n";
        return;
    }

    std::string sampleList = "";
    int count = 0;
    for (const auto& fn : funcs) {
        char buf[64];
        snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)fn.startAddress);
        sampleList += std::string(buf) + " (" + fn.name + "), ";
        if (++count >= 15) break;
    }

    std::string prompt = "Propose optional names for this target binary. Treat every proposal as an AI hypothesis.\n"
                         "Functions sample: " + sampleList + "\n\n"
                         "Generate a markdown table with the observed address, proposed name, supporting evidence, and uncertainty. Do not invent source types or signatures.";

    app.aiService.Send(prompt, app.GetAIContextSummary());

    int timeoutMs = 35000;
    while (app.aiService.State() == openreverse::ai::ChatState::Working && timeoutMs > 0)
    {
        Sleep(100);
        timeoutMs -= 100;
    }

    const auto& conv = app.aiService.Conversation();
    if (!conv.empty() && conv.back().role == "assistant")
    {
        std::cout << "\n\033[1;32m=== GLOBAL AI INFERRED SYMBOL & TYPE PROPAGATION TABLE ===\033[0m\n";
        std::cout << conv.back().content << "\n";
        std::cout << "\033[1;32m==========================================================\033[0m\n\n";
    }
    else
    {
        std::cout << "[-] AI Copilot request failed or timed out: " << app.aiService.Status() << "\n";
    }
}

void CLIRepl::HandleAIVuln(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "Usage: ai-vuln <addr|name>\n";
        return;
    }
    uint64_t addr = ParseAddressOrName(app, args[1]);
    if (addr == 0)
    {
        std::cout << "[-] Function not found: " << args[1] << "\n";
        return;
    }
    const std::string evidence = AssemblySummaryFor(app, addr);
    std::string prompt = "Audit this decoded assembly evidence for potential security issues. Mark uncertainty explicitly:\n```asm\n" + evidence + "\n```";

    std::cout << "[*] Auditing function 0x" << std::hex << addr << std::dec << " for vulnerabilities via AI Copilot...\n";
    app.aiService.Send(prompt, app.GetAIContextSummary());

    int timeoutMs = 25000;
    while (app.aiService.State() == openreverse::ai::ChatState::Working && timeoutMs > 0)
    {
        Sleep(100);
        timeoutMs -= 100;
    }

    const auto& conv = app.aiService.Conversation();
    if (!conv.empty() && conv.back().role == "assistant")
    {
        std::cout << "\n=== AI Vulnerability Audit ===\n" << conv.back().content << "\n==============================\n";
    }
    else
    {
        std::cout << "[-] AI Copilot request failed or timed out: " << app.aiService.Status() << "\n";
    }
}

struct SlashCommandItemInfo {
    std::string cmd;
    std::string desc;
};

static const std::vector<SlashCommandItemInfo> g_interactiveCommands = {
    {"/triage",    "Threat report and automatic MITRE ATT&CK mapping"},
    {"/auto-rename","Global AI name & type inference across all functions"},
    {"/open",      "Open binary file and launch OpenReverse analysis"},
    {"/attach",    "Attach to running Windows process PID for dynamic analysis"},
    {"/functions", "List discovered functions & entry points in target binary"},
    {"/decompile", "Show decoded instructions grouped by basic block"},
    {"/explain",   "Ask AI Copilot to explain current function logic in detail"},
    {"/rename",    "Ask AI to suggest descriptive variable & function names"},
    {"/vuln",      "Audit decoded function evidence for vulnerabilities"},
    {"/xrefs",     "Show all cross-references (CALL, JUMP, MEM) to/from address"},
    {"/strings",   "List extracted ASCII/UTF-16 strings and evidence categories"},
    {"/sessions",  "Manage OpenReverse interactive RE & multi-session workspaces"},
    {"/new",       "Create a new clean session workspace"},
    {"/switch",    "Switch active reverse engineering session ID"},
    {"/models",    "Switch the configured provider model"},
    {"/connect",   "Connect AI provider (Ollama, OpenRouter, Groq Cloud...)"},
    {"/setup",     "One-click interactive AI setup & local model auto-installer"},
    {"/gui",       "Handover the session to the OpenReverse workspace"},
    {"/clear",     "Clear terminal screen"},
    {"/exit",      "Exit OpenReverse"}
};

std::string CLIRepl::ReadInteractiveLine(Application& app, const std::string& targetLabel)
{
    (void)app;
    std::string promptPrefix = "\r\033[2K\033[1;36m[s" + std::to_string(currentSessionId_) + ":" + targetLabel + "]\033[0m \033[1;32m/\033[0m openreverse> ";
    std::string inputBuffer = "";
    bool inSlashMenu = false;
    int selectedIndex = 0;
    int lastMenuLines = 0;

    auto getFiltered = [&]() {
        std::vector<SlashCommandItemInfo> filtered;
        std::string prefix = helpers::ToLower(inputBuffer);
        for (const auto& sc : g_interactiveCommands) {
            if (sc.cmd.find(prefix) == 0) {
                filtered.push_back(sc);
            }
        }
        if (filtered.empty()) filtered = g_interactiveCommands;
        return filtered;
    };

    auto updateScreen = [&]() {
        if (lastMenuLines > 0) {
            std::cout << "\r\033[" << lastMenuLines << "A\033[J";
            lastMenuLines = 0;
        } else {
            std::cout << "\r\033[2K";
        }

        if (inSlashMenu) {
            auto filtered = getFiltered();
            if (selectedIndex >= (int)filtered.size()) selectedIndex = 0;
            if (selectedIndex < 0) selectedIndex = (int)filtered.size() - 1;

            std::cout << "\033[38;5;238m┌──────────────────────────────────────────────────────────────────────────┐\033[0m\n";
            lastMenuLines++;
            int maxShow = (int)std::min((size_t)9, filtered.size());
            for (int idx = 0; idx < maxShow; ++idx) {
                const auto& sc = filtered[idx];
                bool isSel = (idx == selectedIndex);
                std::string cmdPadded = sc.cmd;
                while (cmdPadded.length() < 12) cmdPadded += " ";
                std::string descPadded = sc.desc;
                if (descPadded.length() > 58) descPadded = descPadded.substr(0, 58);
                while (descPadded.length() < 58) descPadded += " ";

                if (isSel) {
                    std::cout << "\033[48;5;208;1;37m│  " << cmdPadded << " " << descPadded << "│\033[0m\n";
                } else {
                    std::cout << "│  \033[38;5;208m" << cmdPadded << "\033[0m " << descPadded << "│\n";
                }
                lastMenuLines++;
            }
            std::cout << "\033[38;5;238m└──────────────────────────────────────────────────────────────────────────┘\033[0m\n";
            std::cout << "  \033[38;5;75mBuild\033[0m \033[38;5;238m·\033[0m \033[1;37mqwen2.5-coder:7b\033[0m \033[38;5;242mLocal Ollama\033[0m\n";
            std::cout << "  \033[1;33mtab\033[0m \033[38;5;242msessions\033[0m   \033[1;33mctrl+p\033[0m \033[38;5;242mcommands\033[0m\n";
            lastMenuLines += 3;
        }

        std::cout << promptPrefix << inputBuffer << std::flush;
    };

    updateScreen();

    while (true)
    {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') // Enter
        {
            if (inSlashMenu) {
                auto filtered = getFiltered();
                if (!filtered.empty() && selectedIndex >= 0 && selectedIndex < (int)filtered.size()) {
                    inputBuffer = filtered[selectedIndex].cmd;
                }
                inSlashMenu = false;
            }
            if (lastMenuLines > 0) {
                std::cout << "\r\033[" << lastMenuLines << "A\033[J";
                lastMenuLines = 0;
            }
            std::cout << promptPrefix << inputBuffer << "\n";
            return inputBuffer;
        }
        else if (ch == 8 || ch == 127) // Backspace
        {
            if (!inputBuffer.empty()) {
                inputBuffer.pop_back();
            }
            inSlashMenu = (!inputBuffer.empty() && inputBuffer[0] == '/');
            selectedIndex = 0;
            updateScreen();
        }
        else if (ch == '\t') // Tab completion
        {
            if (inSlashMenu) {
                auto filtered = getFiltered();
                if (!filtered.empty() && selectedIndex >= 0 && selectedIndex < (int)filtered.size()) {
                    inputBuffer = filtered[selectedIndex].cmd + " ";
                    inSlashMenu = false;
                }
            }
            updateScreen();
        }
        else if (ch == 224 || ch == 0) // Windows arrow key prefix
        {
            int code = _getch();
            if (inSlashMenu) {
                auto filtered = getFiltered();
                if (code == 72) // UP Arrow
                {
                    selectedIndex = (selectedIndex - 1 + (int)filtered.size()) % (int)filtered.size();
                }
                else if (code == 80) // DOWN Arrow
                {
                    selectedIndex = (selectedIndex + 1) % (int)filtered.size();
                }
            }
            updateScreen();
        }
        else if (ch == 27) // ESC
        {
            inSlashMenu = false;
            updateScreen();
        }
        else if (ch == 3) // Ctrl+C
        {
            return "/exit";
        }
        else if (isprint(ch))
        {
            inputBuffer += (char)ch;
            inSlashMenu = (inputBuffer[0] == '/');
            updateScreen();
        }
    }
}

bool CLIRepl::Run(Application& app)
{
    PrintBanner();
    std::string line;
    while (true)
    {
        std::string targetLabel = "no target";
        for (const auto& s : sessions_) {
            if (s.id == currentSessionId_ && !s.targetExe.empty()) {
                targetLabel = s.targetExe;
                break;
            }
        }
        line = ReadInteractiveLine(app, targetLabel);

        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty()) continue;

        std::vector<std::string> args = TokenizeCommand(line);

        std::string cmd = args[0];
        if (cmd[0] == '/' || cmd == "/")
        {
            if (cmd == "/" && args.size() == 1) {
                ShowSlashMenuPopup(app);
            } else {
                std::string slashCmd = helpers::ToLower(cmd);
                HandleSlashCommand(app, slashCmd, args);
            }
            continue;
        }

        std::string lowerCmd = helpers::ToLower(cmd);
        if (lowerCmd == "help" || lowerCmd == "?" || lowerCmd == "openreverse")
        {
            PrintSlashHelp();
        }
        else if (lowerCmd == "attach" || lowerCmd == "p")
        {
            HandleAttach(app, args);
        }
        else if (lowerCmd == "open" || lowerCmd == "o")
        {
            HandleOpen(app, args);
        }
        else if (lowerCmd == "functions" || lowerCmd == "fn")
        {
            HandleFunctions(app, args);
        }
        else if (lowerCmd == "decompile" || lowerCmd == "dec")
        {
            HandleDecompile(app, args);
        }
        else if (cmd == "cfg")
        {
            HandleCFG(app, args);
        }
        else if (cmd == "xrefs" || cmd == "x")
        {
            HandleXRefs(app, args);
        }
        else if (cmd == "strings" || cmd == "str")
        {
            HandleStrings(app, args);
        }
        else if (cmd == "disasm" || cmd == "d")
        {
            HandleDisasm(app, args);
        }
        else if (cmd == "modules" || cmd == "mod")
        {
            HandleModules(app, args);
        }
        else if (cmd == "report")
        {
            HandleReport(app, args);
        }
        else if (cmd == "ai" || cmd == "ai-connect" || cmd == "ai-setup" || cmd == "connect-ai" || cmd == "ai-login" || cmd == "connect" || cmd == "login")
        {
            HandleAIConnect(app, args);
        }
        else if (cmd == "ai-config")
        {
            HandleAIConfig(app, args);
        }
        else if (cmd == "ai-key")
        {
            HandleAIKey(app, args);
        }
        else if (cmd == "ai-model")
        {
            HandleAIModel(app, args);
        }
        else if (cmd == "ai-status")
        {
            HandleAIStatus(app, args);
        }
        else if (cmd == "ai-ask")
        {
            HandleAIAsk(app, args);
        }
        else if (cmd == "ai-explain")
        {
            HandleAIExplain(app, args);
        }
        else if (cmd == "ai-rename")
        {
            HandleAIRename(app, args);
        }
        else if (cmd == "ai-vuln")
        {
            HandleAIVuln(app, args);
        }
        else if (cmd == "gui" || cmd == "studio")
        {
            std::cout << "\n================================================================================\n"
                      << "  [!] THE OPENREVERSE GUI IS A SEPARATE DESKTOP APPLICATION\n"
                      << "================================================================================\n"
                      << "  The OpenReverse CLI ('openreverse') is a 100% shell-only terminal tool.\n"
                      << "  To use the Graphical User Interface (GUI):\n"
                      << "    1. Install it using: " << openreverse::kInstallerFileName << "\n"
                      << "    2. Launch OpenReverse from your Desktop or Start Menu shortcut.\n"
                      << "================================================================================\n\n";
            continue;
        }
        else if (cmd == "exit" || cmd == "quit" || cmd == "q")
        {
            std::cout << "[*] Exiting OpenReverse.\n";
            return false;
        }
        else
        {
            HandleChat(app, line);
        }
    }
    return false;
}

void CLIRepl::PrintSlashHelp()
{
    std::cout << "\n\033[1;36m=================================================================================\033[0m\n";
    std::cout << "\033[1;36m                     OPENREVERSE SLASH COMMANDS REFERENCE                         \033[0m\n";
    std::cout << "\033[1;36m=================================================================================\033[0m\n";
    std::cout << "  \033[1;32m/help\033[0m               Show all slash commands and reverse engineering tools\n";
    std::cout << "  \033[1;32m/setup\033[0m              Configure an AI provider and model\n";
    std::cout << "  \033[1;32m/connect\033[0m [provider] Configure an OpenAI-compatible provider\n";
    std::cout << "  \033[1;32m/open\033[0m <path.exe>    Open a PE file for static analysis\n";
    std::cout << "  \033[1;32m/attach\033[0m <PID>       Attach to a running process PID\n";
    std::cout << "  \033[1;32m/sessions\033[0m           List all active reverse engineering & chat sessions\n";
    std::cout << "  \033[1;32m/new-session\033[0m [name] Create a new clean session workspace\n";
    std::cout << "  \033[1;32m/switch\033[0m <id>        Switch to another active session ID\n";
    std::cout << "  \033[1;32m/functions\033[0m [filt]   List discovered functions in current binary\n";
    std::cout << "  \033[1;32m/decompile\033[0m <addr>   Show decoded control-flow evidence\n";
    std::cout << "  \033[1;32m/xrefs\033[0m <addr>       Show all cross-references (CALL, JUMP, MEM) to/from address\n";
    std::cout << "  \033[1;32m/strings\033[0m [filt]     List extracted strings and evidence categories\n";
    std::cout << "  \033[1;32m/explain\033[0m <addr>     Ask AI to decompile & explain a function in detail\n";
    std::cout << "  \033[1;32m/rename\033[0m <addr>      Ask AI to suggest descriptive variable & function names\n";
    std::cout << "  \033[1;32m/triage\033[0m             Threat report and automatic MITRE ATT&CK mapping\n";
    std::cout << "  \033[1;32m/auto-rename\033[0m        Global AI name & type inference across all functions\n";
    std::cout << "  \033[1;32m/model\033[0m <name>       Change the configured provider model\n";
    std::cout << "  \033[1;32m/gui\033[0m                Handover session immediately to Graphical User Interface\n";
    std::cout << "  \033[1;32m/clear\033[0m              Clear terminal screen\n";
    std::cout << "  \033[1;32m/exit\033[0m               Exit OpenReverse\n";
    std::cout << "\033[1;36m---------------------------------------------------------------------------------\033[0m\n";
    std::cout << "Tip: Any regular message without '/' is sent directly to your AI Copilot as chat!\n\n";
}

void CLIRepl::ShowSlashMenuPopup(Application& app)
{
    (void)app;
    std::cout << "\n\033[38;5;238m┌──────────────────────────────────────────────────────────────────────────┐\033[0m\n";
    for (const auto& sc : g_interactiveCommands) {
        std::string cmdPadded = sc.cmd;
        while (cmdPadded.length() < 12) cmdPadded += " ";
        std::string descPadded = sc.desc;
        if (descPadded.length() > 58) descPadded = descPadded.substr(0, 58);
        while (descPadded.length() < 58) descPadded += " ";
        std::cout << "│  \033[38;5;208m" << cmdPadded << "\033[0m " << descPadded << "│\n";
    }
    std::cout << "\033[38;5;238m└──────────────────────────────────────────────────────────────────────────┘\033[0m\n";
    std::cout << "  \033[38;5;75mBuild\033[0m \033[38;5;238m·\033[0m \033[1;37m" << app.aiService.Model()
              << "\033[0m \033[38;5;238m·\033[0m \033[38;5;242mlocal analysis\033[0m\n";
    std::cout << "  \033[1;33mtab\033[0m \033[38;5;242msessions\033[0m   \033[1;33mctrl+p\033[0m \033[38;5;242mcommands\033[0m\n";
    std::cout << "\033[1;32m/\033[0m ";
}

void CLIRepl::HandleSessions(Application& app, const std::vector<std::string>& args)
{
    (void)args;
    std::cout << "\n=== ACTIVE REVERSE ENGINEERING SESSIONS ===\n";
    for (const auto& s : sessions_)
    {
        bool isCurrent = (s.id == currentSessionId_);
        std::cout << (isCurrent ? "\033[1;32m* [" : "  [") << s.id << "] "
                  << std::left << std::setw(18) << s.name
                  << " | Target: " << (s.targetExe.empty() ? "[No Binary Loaded]" : s.targetExe)
                  << " | PID: " << s.pid
                  << (isCurrent ? " (ACTIVE)\033[0m\n" : "\n");
    }
    std::cout << "===========================================\n";
    std::cout << "Use '/switch <id>' to change session, or '/new-session [name]' to create one.\n\n";
}

void CLIRepl::HandleSessionNew(Application& app, const std::vector<std::string>& args)
{
    int newId = (int)sessions_.size() + 1;
    std::string name = (args.size() > 1) ? args[1] : ("session-" + std::to_string(newId));
    Session s;
    s.id = newId;
    s.name = name;
    s.targetExe = "";
    s.pid = 0;
    s.baseAddress = 0;
    s.functionsCount = 0;
    sessions_.push_back(s);
    currentSessionId_ = newId;
    std::cout << "\033[1;32m[+] Created & switched to new session [" << newId << "]: " << name << "\033[0m\n\n";
}

void CLIRepl::HandleSessionSwitch(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "Usage: /switch <session_id>\n";
        return;
    }
    int targetId = atoi(args[1].c_str());
    for (auto& s : sessions_)
    {
        if (s.id == targetId)
        {
            currentSessionId_ = s.id;
            std::cout << "\033[1;32m[+] Switched active session to [" << s.id << "]: " << s.name << "\033[0m\n\n";
            return;
        }
    }
    std::cout << "\033[1;31m[-] Session ID " << targetId << " not found. Type '/sessions' to list all.\033[0m\n";
}

bool CLIRepl::HandleChat(Application& app, const std::string& userMessage)
{
    std::cout << "\033[1;36m[AI Chat - " << app.aiService.Model() << "]\033[0m Thinking...\n";
    if (!app.aiService.Send(userMessage, app.GetAIContextSummary()))
    {
        std::cout << "\033[1;31m[-] AI request rejected: " << app.aiService.Status() << "\033[0m\n";
        return false;
    }

    int timeoutMs = 30000;
    while (app.aiService.State() == openreverse::ai::ChatState::Working && timeoutMs > 0)
    {
        Sleep(100);
        timeoutMs -= 100;
    }

    const auto& conv = app.aiService.Conversation();
    if (!conv.empty() && conv.back().role == "assistant")
    {
        std::cout << "\n\033[1;37m" << conv.back().content << "\033[0m\n\n";
    }
    else
    {
        std::cout << "\033[1;31m[-] AI request failed or timed out: " << app.aiService.Status() << "\033[0m\n";
        std::cout << "Tip: Use '/connect' to configure or check your API key and provider.\n\n";
    }
    return app.aiService.State() == openreverse::ai::ChatState::Ready;
}

void CLIRepl::HandleSlashCommand(Application& app, const std::string& cmd, const std::vector<std::string>& args)
{
    if (cmd == "/help" || cmd == "/?" || cmd == "/")
    {
        PrintSlashHelp();
    }
    else if (cmd == "/sessions")
    {
        HandleSessions(app, args);
    }
    else if (cmd == "/new-session" || cmd == "/new")
    {
        HandleSessionNew(app, args);
    }
    else if (cmd == "/switch" || cmd == "/session")
    {
        HandleSessionSwitch(app, args);
    }
    else if (cmd == "/connect" || cmd == "/ai" || cmd == "/ai-connect" ||
             cmd == "/setup" || cmd == "/models" || cmd == "/init")
    {
        HandleAIConnect(app, args);
    }
    else if (cmd == "/open" || cmd == "/o")
    {
        if (HandleOpen(app, args))
        {
            for (auto& s : sessions_) {
                if (s.id == currentSessionId_) {
                    s.targetExe = args[1];
                    s.pid = app.attachedPID;
                    s.functionsCount = app.analysisPanel.GetFunctions().size();
                    break;
                }
            }
        }
    }
    else if (cmd == "/attach" || cmd == "/p")
    {
        HandleAttach(app, args);
        for (auto& s : sessions_) {
            if (s.id == currentSessionId_) {
                s.targetExe = app.attachedProcessName;
                s.pid = app.attachedPID;
                s.functionsCount = app.analysisPanel.GetFunctions().size();
                break;
            }
        }
    }
    else if (cmd == "/functions" || cmd == "/fn")
    {
        HandleFunctions(app, args);
    }
    else if (cmd == "/decompile" || cmd == "/dec")
    {
        HandleDecompile(app, args);
    }
    else if (cmd == "/xrefs" || cmd == "/x")
    {
        HandleXRefs(app, args);
    }
    else if (cmd == "/strings" || cmd == "/str")
    {
        HandleStrings(app, args);
    }
    else if (cmd == "/disasm" || cmd == "/d")
    {
        HandleDisasm(app, args);
    }
    else if (cmd == "/modules" || cmd == "/mod")
    {
        HandleModules(app, args);
    }
    else if (cmd == "/report")
    {
        HandleReport(app, args);
    }
    else if (cmd == "/explain" || cmd == "/ai-explain")
    {
        HandleAIExplain(app, args);
    }
    else if (cmd == "/rename" || cmd == "/ai-rename")
    {
        HandleAIRename(app, args);
    }
    else if (cmd == "/vuln" || cmd == "/ai-vuln")
    {
        HandleAIVuln(app, args);
    }
    else if (cmd == "/triage" || cmd == "/ai-triage")
    {
        HandleAITriage(app, args);
    }
    else if (cmd == "/auto-rename" || cmd == "/ai-auto-rename")
    {
        HandleAIAutoRename(app, args);
    }
    else if (cmd == "/model" || cmd == "/ai-model")
    {
        HandleAIModel(app, args);
    }
    else if (cmd == "/status" || cmd == "/ai-status")
    {
        HandleAIStatus(app, args);
    }
    else if (cmd == "/clear" || cmd == "/cls")
    {
        system("cls");
    }
    else if (cmd == "/exit" || cmd == "/quit" || cmd == "/q")
    {
        std::cout << "[*] Exiting OpenReverse.\n";
        exit(0);
    }
    else
    {
        std::cout << "\033[1;31m[-] Unknown slash command: " << cmd << ". Type '/help' for reference.\033[0m\n";
    }
}

std::string CLIRepl::AssemblySummaryFor(Application& app, uint64_t addr)
{
    auto bytes = app.memoryReader.ReadBytes(app.processHandle, addr, 4096);
    if (bytes.empty()) return "";
    auto fi = app.functionAnalyzer.AnalyzeFunction(bytes.data(), bytes.size(), addr, addr, app.disassembler, app.is64Bit, 4096);
    return app.functionAnalyzer.GenerateAssemblySummary(fi, app.is64Bit);
}

} // namespace openreverse
