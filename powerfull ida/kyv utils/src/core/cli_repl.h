#pragma once
// ============================================================================
// KYV - Core: Interactive REPL & Terminal Interpreter (OpenCode / IDA CLI)
// Provides a full interactive shell with ANSI color support, instant
// IDA Studio decompilation, XREF queries, and seamless GUI handover.
// ============================================================================

#include "app/application.h"
#include <string>
#include <vector>

namespace kyv {

class CLIRepl {
public:
    CLIRepl();
    ~CLIRepl();

    // Enable Windows Terminal ANSI escape codes (colors & formatting)
    static void EnableAnsiColors();

    static void PrintOpenCodeHelp();
    static void PrintOpenCodeVersion();

    // Start interactive command-line REPL loop
    // Returns true if user requested to switch to GUI mode ('gui' command)
    // Returns false if user requested to exit ('exit' command)
    bool Run(Application& app);

    void HandleOpen(Application& app, const std::vector<std::string>& args);
    void HandleAttach(Application& app, const std::vector<std::string>& args);
    void HandleAIConnect(Application& app, const std::vector<std::string>& args);
    void HandleSessions(Application& app, const std::vector<std::string>& args);
    void HandleChat(Application& app, const std::string& userMessage);

private:
    void PrintBanner();
    void PrintHelp();
    void HandleFunctions(Application& app, const std::vector<std::string>& args);
    void HandleDecompile(Application& app, const std::vector<std::string>& args);
    void HandleCFG(Application& app, const std::vector<std::string>& args);
    void HandleXRefs(Application& app, const std::vector<std::string>& args);
    void HandleStrings(Application& app, const std::vector<std::string>& args);
    void HandleDisasm(Application& app, const std::vector<std::string>& args);
    void HandleModules(Application& app, const std::vector<std::string>& args);
    void HandleReport(Application& app, const std::vector<std::string>& args);

    // AI Copilot & Model Configuration Commands
    void HandleAIConfig(Application& app, const std::vector<std::string>& args);
    void HandleAIKey(Application& app, const std::vector<std::string>& args);
    void HandleAIModel(Application& app, const std::vector<std::string>& args);
    void HandleAIStatus(Application& app, const std::vector<std::string>& args);
    void HandleAIAsk(Application& app, const std::vector<std::string>& args);
    void HandleAIExplain(Application& app, const std::vector<std::string>& args);
    void HandleAIRename(Application& app, const std::vector<std::string>& args);
    void HandleAIVuln(Application& app, const std::vector<std::string>& args);
    void HandleAITriage(Application& app, const std::vector<std::string>& args);
    void HandleAIAutoRename(Application& app, const std::vector<std::string>& args);

    // Multi-Session & OpenCode Slash Command Management
    struct Session {
        int id = 1;
        std::string name;
        std::string targetExe;
        DWORD pid = 0;
        uint64_t baseAddress = 0;
        size_t functionsCount = 0;
        std::vector<ai::ChatMessage> aiHistory;
    };
    std::vector<Session> sessions_;
    int currentSessionId_ = 1;

    void HandleSessionNew(Application& app, const std::vector<std::string>& args);
    void HandleSessionSwitch(Application& app, const std::vector<std::string>& args);
    void HandleSlashCommand(Application& app, const std::string& cmd, const std::vector<std::string>& args);
    void PrintSlashHelp();
    void ShowSlashMenuPopup(Application& app);
    std::string ReadInteractiveLine(Application& app, const std::string& targetLabel);

    uint64_t ParseAddressOrName(Application& app, const std::string& token);
    std::string DecompileHelper(Application& app, uint64_t addr);
};

} // namespace kyv
