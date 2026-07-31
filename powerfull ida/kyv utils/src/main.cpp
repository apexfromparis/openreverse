// ============================================================================
// KYV - Memory Analysis & Reverse Engineering Tool
// main.cpp - Entry point, Win32 window creation, DirectX 11 + ImGui setup
// ============================================================================

#include "app/application.h"
#include "ui/ui_manager.h"
#include "core/automator.h"
#include "core/cli_repl.h"
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

    kyv::Application app;

    // Check for Headless Automated Decompilation Mode and OpenCode CLI commands
    for (size_t i = 1; i < cmdArgs.size(); ++i)
    {
        std::string arg = cmdArgs[i];
        if (arg == "--decompile-exe" && i + 1 < cmdArgs.size())
        {
            std::string exePath = cmdArgs[i + 1];
            std::string outFile = (i + 2 < cmdArgs.size()) ? cmdArgs[i + 2] : "kyv_decompile_report.md";

            AttachConsole(ATTACH_PARENT_PROCESS);
            freopen("CONOUT$", "w", stdout);
            printf("[+] KYV Headless Engine: Launching and decompiling '%s'...\n", exePath.c_str());

            STARTUPINFOA si = { sizeof(si) };
            PROCESS_INFORMATION pi = {};
            std::string cmd = "\"" + exePath + "\" --daemon";
            if (CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            {
                Sleep(1200);
                kyv::Automator automator;
                auto res = automator.AnalyzeProcess(app, pi.dwProcessId, exePath);
                if (res.success)
                {
                    std::string report = kyv::Automator::FormatReport(res);
                    std::ofstream ofs(outFile);
                    ofs << report;
                    ofs.close();
                    printf("[+] SUCCESS! Report saved to: %s (%zu functions decompiled, %zu XREFs)\n", outFile.c_str(), res.functionsDiscovered, res.totalXrefs);
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
        else if (arg == "--decompile-pid" && i + 1 < cmdArgs.size())
        {
            DWORD targetPid = (DWORD)atoi(cmdArgs[i + 1].c_str());
            std::string outFile = (i + 2 < cmdArgs.size()) ? cmdArgs[i + 2] : "kyv_decompile_report.md";

            AttachConsole(ATTACH_PARENT_PROCESS);
            freopen("CONOUT$", "w", stdout);
            printf("[+] KYV Headless Engine: Starting IDA Pro automated decompilation on PID %lu...\n", targetPid);

            kyv::Automator automator;
            auto res = automator.AnalyzeProcess(app, targetPid);
            if (res.success)
            {
                std::string report = kyv::Automator::FormatReport(res);
                std::ofstream ofs(outFile);
                ofs << report;
                ofs.close();
                printf("[+] SUCCESS! Report saved to: %s (%zu functions decompiled, %zu XREFs)\n", outFile.c_str(), res.functionsDiscovered, res.totalXrefs);
                return 0;
            }
            else
            {
                printf("[-] FAILED to attach or read process PID %lu\n", targetPid);
                return 1;
            }
        }
    }

    // Determine if we should attach to Windows Console for OpenCode CLI commands or TUI mode
    bool isConsoleCommand = (cmdArgs.size() <= 1);
    for (size_t i = 1; i < cmdArgs.size(); ++i)
    {
        std::string arg = cmdArgs[i];
        if (arg == "-h" || arg == "--help" || arg == "help" ||
            arg == "-v" || arg == "--version" || arg == "version" ||
            arg == "models" || arg == "model" ||
            arg == "providers" || arg == "auth" ||
            arg == "setup" || arg == "init" || arg == "install-ai" ||
            arg == "session" || arg == "sessions" ||
            arg == "stats" || arg == "run" ||
            arg == "--cli" || arg == "-c" || arg == "--repl" || arg == "tui" ||
            (i == 1 && arg.find("-") != 0 && GetFileAttributesA(arg.c_str()) != INVALID_FILE_ATTRIBUTES))
        {
            isConsoleCommand = true;
            break;
        }
    }

    if (isConsoleCommand)
    {
        if (!AttachConsole(ATTACH_PARENT_PROCESS))
        {
            AllocConsole();
        }
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == INVALID_HANDLE_VALUE || hOut == nullptr)
        {
            AllocConsole();
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
        }
        freopen("CONIN$", "r", stdin);
        std::ios::sync_with_stdio(true);

        for (size_t i = 1; i < cmdArgs.size(); ++i)
        {
            std::string arg = cmdArgs[i];
            if (arg == "-h" || arg == "--help" || arg == "help")
            {
                kyv::CLIRepl::PrintOpenCodeHelp();
                return 0;
            }
            else if (arg == "-v" || arg == "--version" || arg == "version")
            {
                kyv::CLIRepl::PrintOpenCodeVersion();
                return 0;
            }
            else if (arg == "models" || arg == "model")
            {
                std::cout << "ollama/qwen2.5-coder:7b [FREE LOCAL - DEFAULT]\n"
                          << "ollama/deepseek-coder-v2 [FREE LOCAL]\n"
                          << "ollama/llama3.1:8b [FREE LOCAL]\n"
                          << "lmstudio/qwen2.5-coder-7b-instruct [FREE LOCAL]\n"
                          << "groq/llama-3.3-70b-versatile [FREE TIER]\n"
                          << "openrouter/qwen-2.5-coder-32b-instruct:free [FREE TIER]\n"
                          << "openai/gpt-4o\n"
                          << "anthropic/claude-3-5-sonnet\n"
                          << "gemini/gemini-1.5-pro\n"
                          << "mistral/codestral-latest\n";
                return 0;
            }
            else if (arg == "providers" || arg == "auth" || arg == "setup" || arg == "init" || arg == "install-ai")
            {
                kyv::CLIRepl repl;
                repl.HandleAIConnect(app, {});
                return 0;
            }
            else if (arg == "session" || arg == "sessions")
            {
                kyv::CLIRepl repl;
                repl.HandleSessions(app, {});
                return 0;
            }
            else if (arg == "stats")
            {
                std::cout << "=== OPENREVERSE SESSION STATS ===\n"
                          << "  Active AI Provider: Ollama (Free Local)\n"
                          << "  Model             : qwen2.5-coder:7b\n"
                          << "  Token Usage       : 0 prompt / 0 completion ($0.00 FREE)\n"
                          << "=================================\n";
                return 0;
            }
            else if (arg == "run" && i + 1 < cmdArgs.size())
            {
                std::string prompt = cmdArgs[i + 1];
                for (size_t j = i + 2; j < cmdArgs.size(); ++j) prompt += " " + cmdArgs[j];
                kyv::CLIRepl repl;
                repl.HandleChat(app, prompt);
                return 0;
            }
            else if (arg == "--cli" || arg == "-c" || arg == "--repl" || arg == "tui" ||
                     (i == 1 && arg.find("-") != 0 && GetFileAttributesA(arg.c_str()) != INVALID_FILE_ATTRIBUTES))
            {
                kyv::CLIRepl repl;
                if (i == 1 && arg.find("-") != 0 && arg != "tui")
                {
                    std::vector<std::string> openArgs = { "open", arg };
                    repl.HandleOpen(app, openArgs);
                }
                bool switchToGui = repl.Run(app);
                if (!switchToGui)
                {
                    return 0;
                }
                break;
            }
        }

        if (cmdArgs.size() <= 1)
        {
            kyv::CLIRepl repl;
            bool switchToGui = repl.Run(app);
            if (!switchToGui)
            {
                return 0;
            }
        }
    }

    // If GUI mode was launched with a target executable argument (e.g. openreverse --gui crackme.exe), load it
    for (size_t i = 1; i < cmdArgs.size(); ++i)
    {
        std::string arg = cmdArgs[i];
        if (arg != "--gui" && arg != "-g" && arg.find("-") != 0 && GetFileAttributesA(arg.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            kyv::CLIRepl repl;
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
    wc.lpszClassName = L"KYV_WindowClass";
    RegisterClassExW(&wc);

    // Create window
    HWND hwnd = CreateWindowExW(
        0,
        wc.lpszClassName,
        L"OpenReverse Studio - Agentic Memory Analysis & Reverse Engineering",
        WS_OVERLAPPEDWINDOW,
        100, 100, 1600, 1000,
        nullptr, nullptr, hInstance, nullptr
    );

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

    kyv::UIManager::ApplyTheme();

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

        // Render KYV application
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
