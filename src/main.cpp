#include "app/application.h"
#include "openreverse_version.h"
#include "ui/ui_manager.h"
#include "app/automator.h"
#include "cli/cli_repl.h"
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
#include <windowsx.h>
#include <shellapi.h>
#include <shlobj.h>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static ID3D11Device*            g_pd3dDevice           = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext    = nullptr;
static IDXGISwapChain*          g_pSwapChain           = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;
static UINT                     g_ResizeWidth           = 0;
static UINT                     g_ResizeHeight          = 0;
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
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
            firstArg == "attach" || firstArg == "dump";
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
            else if (arg == "dump" && i + 1 < cmdArgs.size())
            {
                openreverse::DumpImportOptions options;
                try
                {
                    for (size_t option = i + 2; option < cmdArgs.size(); ++option)
                    {
                        if (cmdArgs[option] == "--mapped")
                            options.representation = openreverse::DumpRepresentation::MappedPEImage;
                        else if (cmdArgs[option] == "--base" && option + 1 < cmdArgs.size())
                            options.imageBase = std::stoull(cmdArgs[++option], nullptr, 0);
                        else if (cmdArgs[option] == "--size" && option + 1 < cmdArgs.size())
                            options.moduleSize = std::stoull(cmdArgs[++option], nullptr, 0);
                        else if (cmdArgs[option] == "--module" && option + 1 < cmdArgs.size())
                            options.minidumpModuleBase = std::stoull(cmdArgs[++option], nullptr, 0);
                        else if (cmdArgs[option] == "--arch" && option + 1 < cmdArgs.size())
                        {
                            const std::string architecture = cmdArgs[++option];
                            options.architecture = architecture == "x64" ? openreverse::DumpArchitecture::X64 :
                                architecture == "x86" ? openreverse::DumpArchitecture::X86 :
                                openreverse::DumpArchitecture::Unknown;
                        }
                    }
                }
                catch (...)
                {
                    std::cerr << "Invalid dump metadata. Addresses and sizes accept decimal or 0x-prefixed values.\n";
                    return 1;
                }
                if (options.representation == openreverse::DumpRepresentation::AutoDetect &&
                    (options.imageBase != 0 || options.moduleSize != 0 ||
                     options.architecture != openreverse::DumpArchitecture::Unknown))
                    options.representation = openreverse::DumpRepresentation::RawSnapshot;
                const bool opened = app.OpenDumpFile(cmdArgs[i + 1], options);
                if (opened)
                {
                    const auto& analysis = app.analysisDatabase.GetModules().begin()->second;
                    std::cout << "[+] Static dump analysis completed: " << analysis.functions.size()
                              << " functions, " << analysis.xrefs.size() << " Xrefs, "
                              << analysis.offsets.size() << " offsets\n";
                }
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
        return 0;
    }

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

    // Create a compact borderless workstation window. The native resize frame is
    // retained so snapping/resizing keeps behaving like a normal Windows app,
    // while the non-client chrome is rendered by the application itself.
    RECT workArea = {};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
    const int workWidth = workArea.right - workArea.left;
    const int workHeight = workArea.bottom - workArea.top;
    const int initialWidth = (std::min)(1480, (std::max)(1040, workWidth - 80));
    const int initialHeight = (std::min)(800, (std::max)(680, workHeight - 70));
    const int initialX = workArea.left + (workWidth - initialWidth) / 2;
    const int initialY = workArea.top + (workHeight - initialHeight) / 2;

    HWND hwnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        wc.lpszClassName,
        L"OpenReverse - Reverse Engineering Workspace",
        WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU,
        initialX, initialY, initialWidth, initialHeight,
        nullptr, nullptr, hInstance, nullptr
    );

    HICON hAppIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    if (hAppIcon)
    {
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hAppIcon);
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hAppIcon);
    }

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow == SW_SHOWMAXIMIZED ? SW_SHOWMAXIMIZED : SW_SHOWNORMAL);
    UpdateWindow(hwnd);

    // Keep the DWM shadow/rounded corners while the application draws its chrome.
    BOOL darkMode = TRUE;
    DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &darkMode, sizeof(darkMode));
    DWORD cornerPreference = 2; // DWMWCP_ROUND on Windows 11; ignored on older builds.
    DwmSetWindowAttribute(hwnd, 33 /* DWMWA_WINDOW_CORNER_PREFERENCE */,
        &cornerPreference, sizeof(cornerPreference));

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    openreverse::UIManager::ApplyTheme();

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

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        app.Render();

        ImGui::Render();
        const float clear_color[4] = { 0.012f, 0.025f, 0.038f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0); // VSync
    }

    app.Shutdown();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}
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
    case WM_NCCALCSIZE:
        // Remove the standard caption while preserving WS_THICKFRAME semantics.
        if (wParam == TRUE)
            return 0;
        break;

    case WM_NCHITTEST:
    {
        const LRESULT nativeHit = DefWindowProcW(hWnd, msg, wParam, lParam);
        if (nativeHit != HTCLIENT)
            return nativeHit;

        RECT rect = {};
        GetWindowRect(hWnd, &rect);
        const LONG x = GET_X_LPARAM(lParam);
        const LONG y = GET_Y_LPARAM(lParam);
        const int resizeBorder = IsZoomed(hWnd) ? 0 : 6;

        const bool left = x < rect.left + resizeBorder;
        const bool right = x >= rect.right - resizeBorder;
        const bool top = y < rect.top + resizeBorder;
        const bool bottom = y >= rect.bottom - resizeBorder;
        if (top && left) return HTTOPLEFT;
        if (top && right) return HTTOPRIGHT;
        if (bottom && left) return HTBOTTOMLEFT;
        if (bottom && right) return HTBOTTOMRIGHT;
        if (left) return HTLEFT;
        if (right) return HTRIGHT;
        if (top) return HTTOP;
        if (bottom) return HTBOTTOM;

        // The first 31 client pixels are the custom title bar. Reserve the
        // right edge for the three real window-control buttons.
        if (y < rect.top + 31 && x < rect.right - 108)
            return HTCAPTION;
        return HTCLIENT;
    }

    case WM_GETMINMAXINFO:
    {
        auto* minMax = reinterpret_cast<MINMAXINFO*>(lParam);
        minMax->ptMinTrackSize.x = 1040;
        minMax->ptMinTrackSize.y = 680;

        const HMONITOR monitor = MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
        MONITORINFO info = { sizeof(info) };
        if (GetMonitorInfoW(monitor, &info))
        {
            minMax->ptMaxPosition.x = info.rcWork.left - info.rcMonitor.left;
            minMax->ptMaxPosition.y = info.rcWork.top - info.rcMonitor.top;
            minMax->ptMaxSize.x = info.rcWork.right - info.rcWork.left;
            minMax->ptMaxSize.y = info.rcWork.bottom - info.rcWork.top;
        }
        return 0;
    }

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
int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    return WinMain(GetModuleHandleW(nullptr), nullptr, GetCommandLineA(), SW_SHOWDEFAULT);
}
