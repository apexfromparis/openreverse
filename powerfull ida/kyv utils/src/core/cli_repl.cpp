// ============================================================================
// KYV - Core: Interactive REPL & Terminal Interpreter Implementation
// ============================================================================

#include "cli_repl.h"
#include "automator.h"
#include "ui/panels/ida_pro_panel.h"
#include "utils/helpers.h"
#include "utils/logger.h"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>

namespace kyv {

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
    std::cout << "=================================================================================\n";
    std::cout << "   ___  ____  _____ _   _ ____  _____ __     _____ ____  ____  _____ \n";
    std::cout << "  / _ \\|  _ \\| ____| \\ | |  _ \\| ____|\\ \\   / / ____|  _ \\/ ___|| ____|\n";
    std::cout << " | | | | |_) |  _| |  \\| | |_) |  _|   \\ \\ / /|  _| | |_) \\___ \\|  _|  \n";
    std::cout << " | |_| |  __/| |___| |\\  |  _ <| |___   \\ V / | |___|  _ < ___) | |___ \n";
    std::cout << "  \\___/|_|   |_____|_| \\_|_| \\_\\_____|   \\_/  |_____|_| \\_\\____/|_____|\n";
    std::cout << "---------------------------------------------------------------------------------\n";
    std::cout << "   OPENREVERSE Studio v2.0 | x64 Interactive CLI REPL | AI-Powered Reverse Engine \n";
    std::cout << "=================================================================================\n";
    std::cout << "Type '/' to see slash commands (/help, /open, /sessions...), or type directly to talk with AI.\n\n";
}

void CLIRepl::PrintHelp()
{
    std::cout << "OPENREVERSE Terminal Interactive Commands:\n";
    std::cout << "  open <path.exe>       Launch binary in background & run IDA Studio analysis\n";
    std::cout << "  attach <PID>          Attach to running PID & run IDA Studio analysis\n";
    std::cout << "  functions [filter]    List discovered functions (Addr, Name, Size, V(G), XREFs)\n";
    std::cout << "  decompile <addr|name> Decompile function to Hex-Rays C pseudocode\n";
    std::cout << "  cfg <addr|name>       Display basic block control flow graph & branching\n";
    std::cout << "  xrefs <addr|name>     Show Cross-References (CALL, JUMP, READ, WRITE) to/from addr\n";
    std::cout << "  strings [filter]      Display strings (highlights URL/C2 and Registry paths)\n";
    std::cout << "  disasm <addr> [cnt]   Disassemble hex instructions at memory address\n";
    std::cout << "  modules               List loaded PE modules and base addresses\n";
    std::cout << "  report [file.md]      Export full markdown decompilation report to disk\n";
    std::cout << "---------------------------------------------------------------------------------\n";
    std::cout << "AI Copilot & Model Commands:\n";
    std::cout << "  ai-connect [prov] [key]  Quick Connect / Interactive Setup (openai, anthropic, gemini, groq, ollama)\n";
    std::cout << "  ai-setup / connect       Alias for interactive AI setup wizard\n";
    std::cout << "  ai-config <prov> <url> <mod> Configure AI manually (e.g. OpenAI-compatible https://api.openai.com/v1 gpt-4o)\n";
    std::cout << "  ai-key <api_key>      Set and securely store AI API Key\n";
    std::cout << "  ai-model <model_name> Change active AI model (e.g. gpt-4o, claude-3-5-sonnet, ollama-llama3)\n";
    std::cout << "  ai-status             Display current AI connection status and configuration\n";
    std::cout << "  ai-ask <question>     Ask AI Copilot any reverse engineering question\n";
    std::cout << "  ai-explain <func>     Ask AI to analyze and explain a decompiled function\n";
    std::cout << "  ai-rename <func>      Ask AI to suggest meaningful variable & function names\n";
    std::cout << "  ai-vuln <func>        Ask AI to audit decompiled function for security vulnerabilities\n";
    std::cout << "---------------------------------------------------------------------------------\n";
    std::cout << "  gui                   Switch immediately to Graphical User Interface\n";
    std::cout << "  exit / quit           Exit OPENREVERSE Studio\n\n";
}

uint64_t CLIRepl::ParseAddressOrName(Application& app, const std::string& token)
{
    if (token.empty()) return 0;
    // Check if hex address
    if (token.size() > 2 && (token[0] == '0' && (token[1] == 'x' || token[1] == 'X')))
    {
        return std::stoull(token, nullptr, 16);
    }
    // Search by function name
    for (const auto& fn : app.idaProPanel.GetFunctions())
    {
        if (helpers::ToLower(fn.name) == helpers::ToLower(token) ||
            fn.name.find(token) != std::string::npos)
        {
            return fn.startAddress;
        }
    }
    // Try parse raw hex
    try {
        return std::stoull(token, nullptr, 16);
    } catch (...) {
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
    DWORD pid = (DWORD)std::stoul(args[1]);
    std::cout << "[*] Attaching to PID " << pid << " and starting IDA Studio scan...\n";
    Automator automator;
    auto res = automator.AnalyzeProcess(app, pid);
    if (res.success)
    {
        // Populate GUI panel state so 'gui' command has it ready
        app.idaProPanel.AnalyzeCurrentModule(app);
        std::cout << "\033[1;32m[+] Successfully attached to " << res.targetProcessName << " (0x" << std::hex << res.baseAddress << ")\033[0m\n";
        std::cout << "[+] Functions discovered: \033[1;36m" << std::dec << res.functionsDiscovered << "\033[0m | XREFs: \033[1;36m" << res.totalXrefs << "\033[0m | Strings: \033[1;36m" << res.stringsFound << "\033[0m\n\n";
    }
    else
    {
        std::cout << "\033[1;31m[-] Failed to attach or scan process PID " << pid << "\033[0m\n";
    }
}

void CLIRepl::HandleOpen(Application& app, const std::vector<std::string>& args)
{
    if (args.size() < 2)
    {
        std::cout << "\033[1;31mUsage: open <executable_path>\033[0m\n";
        return;
    }
    std::string exePath = args[1];
    std::cout << "[*] Launching '" << exePath << "' in background daemon mode...\n";
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    std::string cmd = "\"" + exePath + "\" --daemon";
    if (CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        Sleep(1000);
        Automator automator;
        auto res = automator.AnalyzeProcess(app, pi.dwProcessId, exePath);
        if (res.success)
        {
            app.idaProPanel.AnalyzeCurrentModule(app);
            std::cout << "\033[1;32m[+] Target loaded! PID: " << pi.dwProcessId << " | Base: 0x" << std::hex << res.baseAddress << "\033[0m\n";
            std::cout << "[+] Functions: \033[1;36m" << std::dec << res.functionsDiscovered << "\033[0m | XREFs: \033[1;36m" << res.totalXrefs << "\033[0m | Strings: \033[1;36m" << res.stringsFound << "\033[0m\n\n";
        }
        else
        {
            std::cout << "\033[1;31m[-] Failed to scan process memory.\033[0m\n";
            TerminateProcess(pi.hProcess, 0);
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        std::cout << "\033[1;31m[-] CreateProcess failed for: " << exePath << "\033[0m\n";
    }
}

void CLIRepl::HandleFunctions(Application& app, const std::vector<std::string>& args)
{
    auto functions = app.idaProPanel.GetFunctions();
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
        std::cout << "\033[1;36m" << addrStr << "\033[0m  "
                  << std::left << std::setw(28) << fn.name
                  << std::right << std::setw(5) << std::dec << fn.size << " B  "
                  << std::setw(6) << fn.basicBlocks.size() << "  ";

        if (fn.cyclomaticComplexity >= 10)
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
    auto* mod = app.moduleManager.FindModuleByAddress(addr);
    uint64_t baseAddr = mod ? mod->baseAddress : 0x7FF700000000;
    auto bytes = app.memoryReader.ReadBytes(app.processHandle, addr, 4096);
    if (bytes.empty())
    {
        std::cout << "\033[1;31m[-] Could not read memory at 0x" << std::hex << addr << "\033[0m\n";
        return;
    }

    auto fi = app.functionAnalyzer.AnalyzeFunction(bytes.data(), bytes.size(), addr, baseAddr, app.disassembler, app.is64Bit, 4096);
    std::string pseudo = app.functionAnalyzer.GeneratePseudocode(fi, app.is64Bit);

    std::cout << "\n\033[1;32m// ============================================================================\n";
    std::cout << "// KYV HEX-RAYS PSEUDOCODE DECOMPILER | Address: " << helpers::FormatAddress(addr, app.is64Bit) << "\n";
    std::cout << "// Function: " << fi.name << " | Size: " << fi.size << " B | V(G): " << fi.cyclomaticComplexity << "\n";
    std::cout << "// ============================================================================\033[0m\n\n";
    std::cout << "\033[1;36m" << pseudo << "\033[0m\n";
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

    auto* mod = app.moduleManager.FindModuleByAddress(addr);
    uint64_t baseAddr = mod ? mod->baseAddress : 0;
    auto bytes = app.memoryReader.ReadBytes(app.processHandle, addr, 4096);
    auto fi = app.functionAnalyzer.AnalyzeFunction(bytes.data(), bytes.size(), addr, baseAddr, app.disassembler, app.is64Bit, 4096);

    std::cout << "\n\033[1;33m[CFG] Control Flow Graph Basic Blocks for " << fi.name << " (V(G)=" << fi.cyclomaticComplexity << "):\033[0m\n";
    for (size_t i = 0; i < fi.basicBlocks.size(); ++i)
    {
        const auto& bb = fi.basicBlocks[i];
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
        const char* typeStr = (xr.type == XRefType::Call) ? "CALL" : (xr.type == XRefType::Jump) ? "JUMP" : "LEA ";
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

    auto res = app.stringScanner.Scan(app.processHandle, mod->baseAddress, mod->baseAddress + std::min((size_t)mod->size, (size_t)8192000), 4, true, true, 2000);
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
        if (sr.category == "URL / C2")
            std::cout << "\033[1;31m" << std::left << std::setw(14) << sr.category << "\033[0m  ";
        else if (sr.category == "Registry")
            std::cout << "\033[1;33m" << std::left << std::setw(14) << sr.category << "\033[0m  ";
        else
            std::cout << std::left << std::setw(14) << sr.category << "  ";

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
    int lines = (args.size() > 2) ? std::stoi(args[2]) : 15;
    if (addr == 0) return;

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
    std::string outFile = (args.size() > 1) ? args[1] : "kyv_interactive_report.md";
    Automator automator;
    auto res = automator.AnalyzeProcess(app, app.attachedPID, app.attachedProcessName);
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
    std::string provider = "Ollama (Free Local)";
    std::string baseUrl = "http://localhost:11434/v1";
    std::string model = "qwen2.5-coder:7b";
    std::string apiKey = "ollama";

    // 1. One-command preset mode: /connect <provider> [api_key] [model]
    if (args.size() >= 2)
    {
        std::string provInput = helpers::ToLower(args[1]);
        if (provInput == "ollama" || provInput == "local" || provInput == "1")
        {
            provider = "Ollama (Free Local)";
            baseUrl = "http://localhost:11434/v1";
            model = (args.size() >= 3) ? args[2] : "qwen2.5-coder:7b";
            apiKey = "ollama";
        }
        else if (provInput == "lmstudio" || provInput == "lms" || provInput == "lm-studio" || provInput == "2")
        {
            provider = "LM Studio (Free Local)";
            baseUrl = "http://localhost:1234/v1";
            model = (args.size() >= 3) ? args[2] : "qwen2.5-coder-7b-instruct";
            apiKey = "lmstudio";
        }
        else if (provInput == "qwen" || provInput == "qwencoder" || provInput == "qwen-coder")
        {
            provider = "Ollama (Free Local)";
            baseUrl = "http://localhost:11434/v1";
            model = "qwen2.5-coder:7b";
            apiKey = "ollama";
        }
        else if (provInput == "deepseek" || provInput == "deepseek-coder" || provInput == "deepseek-r1")
        {
            provider = "Ollama (Free Local)";
            baseUrl = "http://localhost:11434/v1";
            model = "deepseek-coder-v2";
            apiKey = "ollama";
        }
        else if (provInput == "llama" || provInput == "llama3" || provInput == "llama-3")
        {
            provider = "Ollama (Free Local)";
            baseUrl = "http://localhost:11434/v1";
            model = "llama3.1:8b";
            apiKey = "ollama";
        }
        else if (provInput == "groq" || provInput == "3")
        {
            provider = "Groq Cloud (Free Tier)";
            baseUrl = "https://api.groq.com/openai/v1";
            model = (args.size() >= 4) ? args[3] : "llama-3.3-70b-versatile";
            if (args.size() >= 3) apiKey = args[2];
        }
        else if (provInput == "openrouter" || provInput == "4")
        {
            provider = "OpenRouter (Free Tier)";
            baseUrl = "https://openrouter.ai/api/v1";
            model = (args.size() >= 4) ? args[3] : "qwen/qwen-2.5-coder-32b-instruct:free";
            if (args.size() >= 3) apiKey = args[2];
        }
        else if (provInput == "openai" || provInput == "5" || provInput == "gpt")
        {
            provider = "OpenAI";
            baseUrl = "https://api.openai.com/v1";
            model = (args.size() >= 4) ? args[3] : "gpt-4o";
            if (args.size() >= 3) apiKey = args[2];
        }
        else if (provInput == "anthropic" || provInput == "claude" || provInput == "6")
        {
            provider = "Anthropic";
            baseUrl = "https://api.anthropic.com/v1";
            model = (args.size() >= 4) ? args[3] : "claude-3-5-sonnet";
            if (args.size() >= 3) apiKey = args[2];
        }
        else if (provInput == "gemini" || provInput == "google" || provInput == "7")
        {
            provider = "Google Gemini";
            baseUrl = "https://generativelanguage.googleapis.com/v1beta/openai/";
            model = (args.size() >= 4) ? args[3] : "gemini-1.5-pro";
            if (args.size() >= 3) apiKey = args[2];
        }
        else if (provInput == "mistral" || provInput == "8")
        {
            provider = "Mistral AI";
            baseUrl = "https://api.mistral.ai/v1";
            model = (args.size() >= 4) ? args[3] : "codestral-latest";
            if (args.size() >= 3) apiKey = args[2];
        }
        else
        {
            std::cout << "\033[1;31m[-] Unknown AI provider: " << args[1] << "\033[0m\n";
            std::cout << "Available Free presets: ollama, lmstudio, qwen, deepseek, llama, groq, openrouter\n";
            std::cout << "Available Cloud presets: openai, anthropic, gemini, mistral\n";
            std::cout << "Or type '/connect' without arguments for the interactive setup wizard.\n";
            return;
        }
    }
    else
    {
        // 2. Interactive Setup Wizard (FREE by Default)
        std::cout << "\n\033[1;36m=================================================================================\033[0m\n";
        std::cout << "\033[1;36m                  OPENREVERSE AI COPILOT - QUICK CONNECT WIZARD                  \033[0m\n";
        std::cout << "\033[1;36m=================================================================================\033[0m\n";
        std::cout << "Select your AI provider (Free Local options selected by default):\n";
        std::cout << "  \033[1;32m1)\033[0m Ollama        \033[1;32m[FREE/LOCAL]\033[0m (Qwen-2.5-Coder, DeepSeek-Coder, Llama 3.1)\n";
        std::cout << "  \033[1;32m2)\033[0m LM Studio     \033[1;32m[FREE/LOCAL]\033[0m (Qwen, DeepSeek, Llama on localhost:1234)\n";
        std::cout << "  \033[1;32m3)\033[0m Groq Cloud    \033[1;32m[FREE TIER]\033[0m  (Llama-3.3-70B, Qwen-2.5-Coder - Ultra Fast)\n";
        std::cout << "  \033[1;32m4)\033[0m OpenRouter    \033[1;32m[FREE TIER]\033[0m  (Free DeepSeek-R1, Qwen-Coder-32B & all models)\n";
        std::cout << "  \033[1;32m5)\033[0m OpenAI         (GPT-4o, GPT-4o-mini, o1, o3-mini)\n";
        std::cout << "  \033[1;32m6)\033[0m Anthropic      (Claude 3.5 Sonnet, Claude 3 Opus)\n";
        std::cout << "  \033[1;32m7)\033[0m Google Gemini  (Gemini 1.5 Pro, Gemini 1.5 Flash)\n";
        std::cout << "  \033[1;32m8)\033[0m Mistral AI     (Codestral, Mistral Large)\n";
        std::cout << "  \033[1;32m9)\033[0m Custom         (Any OpenAI-compatible API server)\n";
        std::cout << "\033[1;36m---------------------------------------------------------------------------------\033[0m\n";
        std::cout << "Enter provider [1-9] (default 1 - Ollama Free Local): ";

        std::string choiceLine;
        std::getline(std::cin, choiceLine);
        int choice = 1;
        if (!choiceLine.empty()) choice = atoi(choiceLine.c_str());
        if (choice < 1 || choice > 9) choice = 1;

        if (choice == 1)      { provider = "Ollama (Free Local)";    baseUrl = "http://localhost:11434/v1";                              model = "qwen2.5-coder:7b";               apiKey = "ollama"; }
        else if (choice == 2) { provider = "LM Studio (Free Local)"; baseUrl = "http://localhost:1234/v1";                               model = "qwen2.5-coder-7b-instruct";      apiKey = "lmstudio"; }
        else if (choice == 3) { provider = "Groq Cloud (Free Tier)"; baseUrl = "https://api.groq.com/openai/v1";                         model = "llama-3.3-70b-versatile"; }
        else if (choice == 4) { provider = "OpenRouter (Free Tier)"; baseUrl = "https://openrouter.ai/api/v1";                           model = "qwen/qwen-2.5-coder-32b-instruct:free"; }
        else if (choice == 5) { provider = "OpenAI";                 baseUrl = "https://api.openai.com/v1";                              model = "gpt-4o"; }
        else if (choice == 6) { provider = "Anthropic";              baseUrl = "https://api.anthropic.com/v1";                           model = "claude-3-5-sonnet"; }
        else if (choice == 7) { provider = "Google Gemini";          baseUrl = "https://generativelanguage.googleapis.com/v1beta/openai/"; model = "gemini-1.5-pro"; }
        else if (choice == 8) { provider = "Mistral AI";             baseUrl = "https://api.mistral.ai/v1";                              model = "codestral-latest"; }
        else if (choice == 9) {
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
            std::cout << "Select Local Free Model:\n";
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

    if (!apiKey.empty() && apiKey != "ollama" && apiKey != "lmstudio")
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
    else if (apiKey == "ollama" || apiKey == "lmstudio")
    {
        app.aiService.SaveApiKey(apiKey);
    }

    app.aiService.Configure(provider, baseUrl, model);

    std::cout << "\n\033[1;32m=================================================================================\033[0m\n";
    std::cout << "\033[1;32m[+] AI Copilot Successfully Connected!\033[0m\n";
    std::cout << "    Provider   : \033[1;36m" << app.aiService.Provider() << "\033[0m\n";
    std::cout << "    Base URL   : \033[1;36m" << app.aiService.BaseUrl() << "\033[0m\n";
    std::cout << "    Model      : \033[1;36m" << app.aiService.Model() << "\033[0m\n";
    std::cout << "    Key Status : \033[1;36m" << (app.aiService.HasSavedApiKey() ? "Ready (Secured in Credential Manager)" : "Not Saved (using environment or memory)") << "\033[0m\n";
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
    app.aiService.Send(prompt, nullptr);

    int timeoutMs = 25000;
    while (app.aiService.State() == kyv::ai::ChatState::Working && timeoutMs > 0)
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
    std::string pseudo = DecompileHelper(app, addr);
    std::string prompt = "Analyze this decompiled C/C++ function from an x64 binary and explain what it does in detail:\n```c\n" + pseudo + "\n```";

    std::cout << "[*] Explaining function 0x" << std::hex << addr << std::dec << " via AI Copilot...\n";
    app.aiService.Send(prompt, nullptr);

    int timeoutMs = 25000;
    while (app.aiService.State() == kyv::ai::ChatState::Working && timeoutMs > 0)
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
    std::string pseudo = DecompileHelper(app, addr);
    std::string prompt = "Analyze this decompiled C function and suggest clean, descriptive function names and variable names formatted as a markdown table:\n```c\n" + pseudo + "\n```";

    std::cout << "[*] Asking AI Copilot for renaming suggestions for 0x" << std::hex << addr << std::dec << "...\n";
    app.aiService.Send(prompt, nullptr);

    int timeoutMs = 25000;
    while (app.aiService.State() == kyv::ai::ChatState::Working && timeoutMs > 0)
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
    std::string pseudo = DecompileHelper(app, addr);
    std::string prompt = "Audit this decompiled C function for security vulnerabilities (buffer overflows, format strings, logic flaws, integer overflows) and report severity:\n```c\n" + pseudo + "\n```";

    std::cout << "[*] Auditing function 0x" << std::hex << addr << std::dec << " for vulnerabilities via AI Copilot...\n";
    app.aiService.Send(prompt, nullptr);

    int timeoutMs = 25000;
    while (app.aiService.State() == kyv::ai::ChatState::Working && timeoutMs > 0)
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

bool CLIRepl::Run(Application& app)
{
    PrintBanner();
    std::string line;
    while (true)
    {
        // OpenCode style prompt showing current session & loaded target
        std::string targetLabel = "no target";
        for (const auto& s : sessions_) {
            if (s.id == currentSessionId_ && !s.targetExe.empty()) {
                targetLabel = s.targetExe;
                break;
            }
        }
        std::cout << "\033[1;36m[s" << currentSessionId_ << ":" << targetLabel << "]\033[0m \033[1;32m/\033[0m openreverse> ";
        if (!std::getline(std::cin, line))
        {
            break;
        }

        // Trim leading and trailing spaces
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty()) continue;

        std::vector<std::string> args;
        std::istringstream iss(line);
        std::string token;
        while (iss >> token) args.push_back(token);

        std::string cmd = args[0];
        // 1. If command starts with '/' OR is '/' -> Handle as OpenCode slash command
        if (cmd[0] == '/' || cmd == "/")
        {
            if (cmd == "/" && args.size() == 1) {
                PrintSlashHelp();
            } else {
                std::string slashCmd = helpers::ToLower(cmd);
                HandleSlashCommand(app, slashCmd, args);
            }
            continue;
        }

        // 2. Legacy commands support (without slash) for backward compatibility
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
        else if (cmd == "gui")
        {
            std::cout << "[*] Handing over session to Graphical User Interface...\n";
            return true;
        }
        else if (cmd == "exit" || cmd == "quit" || cmd == "q")
        {
            std::cout << "[*] Exiting OPENREVERSE Studio.\n";
            return false;
        }
        else
        {
            // 3. OpenCode natural chat behavior: anything not recognized as a command is treated as a prompt to the AI!
            HandleChat(app, line);
        }
    }
    return false;
}

void CLIRepl::PrintSlashHelp()
{
    std::cout << "\n\033[1;36m=================================================================================\033[0m\n";
    std::cout << "\033[1;36m                OPENREVERSE / OPENCODE SLASH COMMANDS REFERENCE                  \033[0m\n";
    std::cout << "\033[1;36m=================================================================================\033[0m\n";
    std::cout << "  \033[1;32m/help\033[0m               Show all slash commands and reverse engineering tools\n";
    std::cout << "  \033[1;32m/connect\033[0m [provider] Quick Connect / Interactive Setup (openai, anthropic, groq...)\n";
    std::cout << "  \033[1;32m/open\033[0m <path.exe>    Launch binary & run full automatic static/dynamic analysis\n";
    std::cout << "  \033[1;32m/attach\033[0m <PID>       Attach to a running process PID\n";
    std::cout << "  \033[1;32m/sessions\033[0m           List all active reverse engineering & chat sessions\n";
    std::cout << "  \033[1;32m/new-session\033[0m [name] Create a new clean session workspace\n";
    std::cout << "  \033[1;32m/switch\033[0m <id>        Switch to another active session ID\n";
    std::cout << "  \033[1;32m/functions\033[0m [filt]   List discovered functions in current binary\n";
    std::cout << "  \033[1;32m/decompile\033[0m <addr>   Decompile x64 assembly to C/C++ Hex-Rays pseudocode\n";
    std::cout << "  \033[1;32m/xrefs\033[0m <addr>       Show all cross-references (CALL, JUMP, MEM) to/from address\n";
    std::cout << "  \033[1;32m/strings\033[0m [filt]     List extracted ASCII/UTF-16 strings (URLs, C2, Registry)\n";
    std::cout << "  \033[1;32m/explain\033[0m <addr>     Ask AI to decompile & explain a function in detail\n";
    std::cout << "  \033[1;32m/rename\033[0m <addr>      Ask AI to suggest descriptive variable & function names\n";
    std::cout << "  \033[1;32m/vuln\033[0m <addr>        Audit decompiled function for security vulnerabilities\n";
    std::cout << "  \033[1;32m/model\033[0m <name>       Change AI model (gpt-4o, claude-3-5-sonnet, llama3...)\n";
    std::cout << "  \033[1;32m/gui\033[0m                Handover session immediately to Graphical User Interface\n";
    std::cout << "  \033[1;32m/clear\033[0m              Clear terminal screen\n";
    std::cout << "  \033[1;32m/exit\033[0m               Exit OPENREVERSE Studio\n";
    std::cout << "\033[1;36m---------------------------------------------------------------------------------\033[0m\n";
    std::cout << "Tip: Any regular message without '/' is sent directly to your AI Copilot as chat!\n\n";
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

void CLIRepl::HandleChat(Application& app, const std::string& userMessage)
{
    std::cout << "\033[1;36m[AI Chat - " << app.aiService.Model() << "]\033[0m Thinking...\n";
    app.aiService.Send(userMessage, nullptr);

    int timeoutMs = 30000;
    while (app.aiService.State() == kyv::ai::ChatState::Working && timeoutMs > 0)
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
    else if (cmd == "/connect" || cmd == "/login" || cmd == "/ai" || cmd == "/ai-connect")
    {
        HandleAIConnect(app, args);
    }
    else if (cmd == "/open" || cmd == "/o")
    {
        HandleOpen(app, args);
        for (auto& s : sessions_) {
            if (s.id == currentSessionId_) {
                s.targetExe = (args.size() > 1) ? args[1] : "";
                s.pid = app.attachedPID;
                s.functionsCount = app.idaProPanel.GetFunctions().size();
                break;
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
                s.functionsCount = app.idaProPanel.GetFunctions().size();
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
        std::cout << "[*] Exiting OPENREVERSE Studio.\n";
        exit(0);
    }
    else
    {
        std::cout << "\033[1;31m[-] Unknown slash command: " << cmd << ". Type '/help' for reference.\033[0m\n";
    }
}

std::string CLIRepl::DecompileHelper(Application& app, uint64_t addr)
{
    auto* mod = app.moduleManager.FindModuleByAddress(addr);
    uint64_t baseAddr = mod ? mod->baseAddress : 0x7FF700000000;
    auto bytes = app.memoryReader.ReadBytes(app.processHandle, addr, 4096);
    if (bytes.empty()) return "";
    auto fi = app.functionAnalyzer.AnalyzeFunction(bytes.data(), bytes.size(), addr, baseAddr, app.disassembler, app.is64Bit, 4096);
    return app.functionAnalyzer.GeneratePseudocode(fi, app.is64Bit);
}

} // namespace kyv
