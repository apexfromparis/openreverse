// ============================================================================
// OpenReverse application entry point and DirectX 11 setup.
// ============================================================================

#include "app/application.h"
#include "ui/ui_manager.h"
#include "core/automator.h"
#include "core/cli_repl.h"
#include <algorithm>
#include <fstream>
#include <iostream>

#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>

#include <d3d11.h>
#include <dxgi.h>
#include <dwmapi.h>
#include <tchar.h>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ─── DirectX 11 Globals ──────────────────────────────────────────────────────
static ID3D11Device*            g_pd3dDevice           = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext    = nullptr;
static IDXGISwapChain*          g_pSwapChain           = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;
static UINT                     g_ResizeWidth           = 0;
static UINT                     g_ResizeHeight          = 0;

// ─── Forward Declarations ────────────────────────────────────────────────────
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ─── Entry Point ─────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;

    int cmdArgc = 0;
    LPWSTR* cmdArgvW = CommandLineToArgvW(GetCommandLineW(), &cmdArgc);
    std::vector<std::string> cmdArgs;
    if (cmdArgvW)
    {
        for (int i = 0; i < cmdArgc; ++i)
        {
            char buf[2048] = {};
            WideCharToMultiByte(CP_UTF8, 0, cmdArgvW[i], -1, buf, sizeof(buf), nullptr, nullptr);
            cmdArgs.push_back(buf);
        }
        LocalFree(cmdArgvW);
    }

    openreverse::Application app;

    // Handle headless analysis commands before starting the graphical shell.
    for (size_t i = 1; i < cmdArgs.size(); ++i)
    {
        std::string arg = cmdArgs[i];
        if (arg == "--decompile-exe" && i + 1 < cmdArgs.size())
        {
            std::string exePath = cmdArgs[i + 1];
            std::string outFile = (i + 2 < cmdArgs.size()) ? cmdArgs[i + 2] : "openreverse_decompile_report.md";

            AttachConsole(ATTACH_PARENT_PROCESS);
            freopen("CONOUT$", "w", stdout);
            printf("[+] OpenReverse: launching and analyzing '%s'...\n", exePath.c_str());

            STARTUPINFOA si = { sizeof(si) };
            PROCESS_INFORMATION pi = {};
            std::string cmd = "\"" + exePath + "\" --daemon";
            if (CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            {
                Sleep(1200);
                openreverse::Automator automator;
                auto res = automator.AnalyzeProcess(app, pi.dwProcessId, exePath);
                if (res.success)
                {
                    std::string report = openreverse::Automator::FormatReport(res);
                    std::ofstream ofs(outFile);
                    ofs << report;
                    ofs.close();
                    printf("[+] Report saved to: %s (%zu functions, %zu XREFs)\n", outFile.c_str(), res.functionsDiscovered, res.totalXrefs);
                }
                else
                {
                    printf("[-] FAILED to analyze target process PID %lu\n", pi.dwProcessId);
                }
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return res.success ? 0 : 1;
            }
            else
            {
                printf("[-] FAILED to launch executable: %s\n", exePath.c_str());
                return 1;
            }
        }
        else if (arg == "--test-ai-context" && i + 1 < cmdArgs.size())
        {
            std::string exePath = cmdArgs[i + 1];
            AttachConsole(ATTACH_PARENT_PROCESS);
            freopen("CONOUT$", "w", stdout);
            printf("[+] OpenReverse Testing AI Context Injection on '%s'...\n", exePath.c_str());
            STARTUPINFOA si = { sizeof(si) };
            PROCESS_INFORMATION pi = {};
            if (CreateProcessA(exePath.c_str(), nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
            {
                app.AttachToProcess(pi.dwProcessId);
                openreverse::Automator automator;
                auto res = automator.AnalyzeProcess(app, pi.dwProcessId, exePath);
                app.idaProPanel.AnalyzeCurrentModule(app);
                std::string summary = app.GetAIContextSummary();
                printf("=== TESTED AI CONTEXT SUMMARY OUTPUT ===\n%s\n========================================\n", summary.c_str());
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return 0;
            }
            else
            {
                printf("[-] FAILED to launch executable: %s\n", exePath.c_str());
                return 1;
            }
        }
        else if (arg == "--test-ai-chat" && i + 2 < cmdArgs.size())
        {
            std::string exePath = cmdArgs[i + 1];
            std::string question = cmdArgs[i + 2];
            AttachConsole(ATTACH_PARENT_PROCESS);
            freopen("CONOUT$", "w", stdout);
            printf("[+] OpenReverse Testing AI Chat with live context on '%s'...\n", exePath.c_str());
            STARTUPINFOA si = { sizeof(si) };
            PROCESS_INFORMATION pi = {};
            std::string cmd = "\"" + exePath + "\"";
            if (CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            {
                Sleep(1200);
                app.AttachToProcess(pi.dwProcessId);
                openreverse::Automator automator;
                auto res = automator.AnalyzeProcess(app, pi.dwProcessId, exePath);
                app.idaProPanel.AnalyzeCurrentModule(app);
                if (!app.idaProPanel.GetFunctions().empty())
                {
                    app.currentAddress = app.idaProPanel.GetFunctions()[0].startAddress;
                    app.idaProPanel.SelectFunction(app, app.currentAddress);
                }
                std::string summary = app.GetAIContextSummary();
                app.aiService.Send(question, nullptr, summary);
                int timeoutMs = 35000;
                while (app.aiService.State() == openreverse::ai::ChatState::Working && timeoutMs > 0)
                {
                    Sleep(100);
                    timeoutMs -= 100;
                }
                std::string aiReply = "No response";
                const auto& conv = app.aiService.Conversation();
                if (!conv.empty() && conv.back().role == "assistant")
                {
                    aiReply = conv.back().content;
                }
                std::ofstream ofs("ai_chat_test_report.md");
                ofs << "# OpenReverse AI Chat Test Report\n\n";
                ofs << "## Question\n" << question << "\n\n";
                ofs << "## AI Response\n" << aiReply << "\n\n";
                ofs << "## Injected Context Summary\n```\n" << summary << "\n```\n";
                ofs.close();
                printf("[+] AI Test complete! Saved to ai_chat_test_report.md\n");
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return 0;
            }
            else
            {
                printf("[-] FAILED to launch executable: %s\n", exePath.c_str());
                return 1;
            }
        }
        else if (arg == "--decompile-pid" && i + 1 < cmdArgs.size())
        {
            DWORD targetPid = (DWORD)atoi(cmdArgs[i + 1].c_str());
            std::string outFile = (i + 2 < cmdArgs.size()) ? cmdArgs[i + 2] : "openreverse_decompile_report.md";

            AttachConsole(ATTACH_PARENT_PROCESS);
            freopen("CONOUT$", "w", stdout);
            printf("[+] OpenReverse Headless Engine: Starting automated analysis on PID %lu...\n", targetPid);

            openreverse::Automator automator;
            auto res = automator.AnalyzeProcess(app, targetPid);
            if (res.success)
            {
                std::string report = openreverse::Automator::FormatReport(res);
                std::ofstream ofs(outFile);
                ofs << report;
                ofs.close();
                printf("[+] Report saved to: %s (%zu functions, %zu XREFs)\n", outFile.c_str(), res.functionsDiscovered, res.totalXrefs);
                return 0;
            }
            else
            {
                printf("[-] FAILED to attach or read process PID %lu\n", targetPid);
                return 1;
            }
        }
    }

    // Determine whether this executable was launched as the CLI.
    char exePathBuf[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, exePathBuf, MAX_PATH);
    std::string fullExePath = exePathBuf;
    std::string exeName = fullExePath.substr(fullExePath.find_last_of("/\\") + 1);
    for (auto& c : exeName) c = tolower(c);
    const bool guiRequested = std::find(cmdArgs.begin() + 1, cmdArgs.end(), "--gui") != cmdArgs.end() ||
                              std::find(cmdArgs.begin() + 1, cmdArgs.end(), "-g") != cmdArgs.end();
    bool cliRequested = exeName.find("cli") != std::string::npos;
    if (cmdArgs.size() > 1)
    {
        const std::string& firstArg = cmdArgs[1];
        cliRequested = cliRequested || firstArg == "--cli" || firstArg == "-h" || firstArg == "--help" ||
            firstArg == "help" || firstArg == "-v" || firstArg == "--version" || firstArg == "version" ||
            firstArg == "models" || firstArg == "model" || firstArg == "providers" || firstArg == "auth" ||
            firstArg == "setup" || firstArg == "init" || firstArg == "install-ai" || firstArg == "session" ||
            firstArg == "sessions" || firstArg == "stats" || firstArg == "run" || firstArg == "open" ||
            firstArg == "attach" || firstArg == "--uninstall" || firstArg == "uninstall" || firstArg == "/uninstall";
    }
    const bool isCliExe = !guiRequested && exeName.find("setup") == std::string::npos && cliRequested;

    if (isCliExe)
    {
        // The CLI process must not create a GUI window.
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == INVALID_HANDLE_VALUE || hOut == nullptr)
        {
            if (!AttachConsole(ATTACH_PARENT_PROCESS))
            {
                AllocConsole();
            }
            FILE* fp = nullptr;
            freopen_s(&fp, "CONOUT$", "w", stdout);
            freopen_s(&fp, "CONOUT$", "w", stderr);
            freopen_s(&fp, "CONIN$", "r", stdin);
        }
        std::ios::sync_with_stdio(true);

        for (size_t i = 1; i < cmdArgs.size(); ++i)
        {
            std::string arg = cmdArgs[i];
            if (arg == "-h" || arg == "--help" || arg == "help")
            {
                openreverse::CLIRepl::PrintCLIHelp();
                return 0;
            }
            else if (arg == "-v" || arg == "--version" || arg == "version")
            {
                openreverse::CLIRepl::PrintCLIVersion();
                return 0;
            }
            else if (arg == "models" || arg == "model")
            {
                std::cout << "Configured provider: " << app.aiService.Provider() << "\n"
                          << "Configured model   : " << app.aiService.Model() << "\n"
                          << "Dynamic provider model discovery is not implemented yet.\n";
                return 0;
            }
            else if (arg == "--uninstall" || arg == "uninstall" || arg == "/uninstall")
            {
                int c = MessageBoxA(NULL,
                    "Remove OpenReverse Studio shortcuts and uninstall registration?",
                    "OpenReverse Studio Uninstaller",
                    MB_YESNO | MB_ICONQUESTION);
                if (c == IDYES)
                {
                    char desktopPath[MAX_PATH];
                    if (SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT, desktopPath) == S_OK)
                        DeleteFileA((std::string(desktopPath) + "\\OpenReverse Studio.lnk").c_str());
                    char startMenuPath[MAX_PATH];
                    if (SHGetFolderPathA(NULL, CSIDL_PROGRAMS, NULL, SHGFP_TYPE_CURRENT, startMenuPath) == S_OK)
                        DeleteFileA((std::string(startMenuPath) + "\\OpenReverse Studio.lnk").c_str());
                    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OpenReverseStudio");

                    MessageBoxA(NULL, "Shortcuts and uninstall registration were removed. The application files were not deleted.",
                                "Uninstall Complete", MB_ICONINFORMATION);
                }
                return 0;
            }
            else if (arg == "providers" || arg == "auth" || arg == "setup" || arg == "init" || arg == "install-ai")
            {
                openreverse::CLIRepl repl;
                repl.HandleAIConnect(app, {});
                return 0;
            }
            else if (arg == "session" || arg == "sessions")
            {
                openreverse::CLIRepl repl;
                repl.HandleSessions(app, {});
                return 0;
            }
            else if (arg == "stats")
            {
                std::cout << "=== OPENREVERSE SESSION STATS ===\n"
                          << "  Active AI Provider: " << app.aiService.Provider() << "\n"
                          << "  Model             : " << app.aiService.Model() << "\n"
                          << "  Token/cost telemetry is not collected by this build.\n"
                          << "=================================\n";
                return 0;
            }
            else if (arg == "run" && i + 1 < cmdArgs.size())
            {
                std::string prompt = cmdArgs[i + 1];
                for (size_t j = i + 2; j < cmdArgs.size(); ++j) prompt += " " + cmdArgs[j];
                openreverse::CLIRepl repl;
                return repl.HandleChat(app, prompt) ? 0 : 1;
            }
            else if (arg == "open" && i + 1 < cmdArgs.size())
            {
                std::string targetPath = cmdArgs[i + 1];
                std::vector<std::string> openArgs = { "open", targetPath };
                openreverse::CLIRepl repl;
                const bool opened = repl.HandleOpen(app, openArgs);
                std::cout.flush();
                fflush(stdout);
                return opened ? 0 : 1;
            }
            else if (arg == "attach" && i + 1 < cmdArgs.size())
            {
                openreverse::CLIRepl repl;
                repl.HandleAttach(app, {"attach", cmdArgs[i + 1]});
                return app.isAttached ? 0 : 1;
            }
        }

        openreverse::CLIRepl repl;
        repl.Run(app);
        return 0; // 100% CLI mode: ALWAYS exit when shell ends! Never switch to GUI!
    }

    // If GUI mode was launched with a target executable argument (e.g. openreverse --gui crackme.exe), load it
    for (size_t i = 1; i < cmdArgs.size(); ++i)
    {
        std::string arg = cmdArgs[i];
        if (arg != "--gui" && arg != "-g" && arg.find("-") != 0 && GetFileAttributesA(arg.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            openreverse::CLIRepl repl;
            std::vector<std::string> openArgs = { "open", arg };
            repl.HandleOpen(app, openArgs);
            break;
        }
    }

    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(WNDCLASSEXW);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    wc.hIconSm       = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    wc.lpszClassName = L"OpenReverse_WindowClass";
    RegisterClassExW(&wc);

    // Create window
    HWND hwnd = CreateWindowExW(
        0,
        wc.lpszClassName,
        L"OpenReverse Studio - Memory Analysis & Reverse Engineering",
        WS_OVERLAPPEDWINDOW,
        100, 100, 1600, 1000,
        nullptr, nullptr, hInstance, nullptr
    );

    HICON hAppIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    if (hAppIcon)
    {
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hAppIcon);
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hAppIcon);
    }

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWMAXIMIZED);
    UpdateWindow(hwnd);

    // Enable dark title bar (Windows 10+)
    BOOL darkMode = TRUE;
    DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &darkMode, sizeof(darkMode));

    // Initialize ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

    // Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    openreverse::UIManager::ApplyTheme();

    // Main loop
    bool running = true;
    while (running)
    {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                running = false;
        }
        if (!running)
            break;

        // Handle resize
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        // Start ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Render OpenReverse application
        app.Render();

        // Rendering
        ImGui::Render();
        const float clear_color[4] = { 0.05f, 0.05f, 0.07f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0); // VSync
    }

    // Cleanup
    app.Shutdown();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

// ─── DirectX 11 Helpers ──────────────────────────────────────────────────────
bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount                        = 2;
    sd.BufferDesc.Width                   = 0;
    sd.BufferDesc.Height                  = 0;
    sd.BufferDesc.Format                  = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator   = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags                              = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage                        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow                       = hWnd;
    sd.SampleDesc.Count                   = 1;
    sd.SampleDesc.Quality                 = 0;
    sd.Windowed                           = TRUE;
    sd.SwapEffect                         = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        createDeviceFlags, featureLevelArray, 2,
        D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext
    );
    if (hr == DXGI_ERROR_UNSUPPORTED)
    {
        hr = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
            createDeviceFlags, featureLevelArray, 2,
            D3D11_SDK_VERSION, &sd, &g_pSwapChain,
            &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext
        );
    }
    if (FAILED(hr))
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain)       { g_pSwapChain->Release();        g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release();  g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)       { g_pd3dDevice->Release();         g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth  = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;

    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == SC_KEYMENU)
            return 0;
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ─── Standard Console Entry Point (for native CONSOLE subsystem) ─────────────
int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    return WinMain(GetModuleHandleW(nullptr), nullptr, GetCommandLineA(), SW_SHOWDEFAULT);
}
