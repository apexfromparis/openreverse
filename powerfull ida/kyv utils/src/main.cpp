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

    // Check for Headless Automated Decompilation Mode
    // Usage: KYV.exe --decompile-exe <exe_path> [output_file.md]
    //        KYV.exe --decompile-pid <PID> [output_file.md]
    for (int i = 1; i < __argc; ++i)
    {
        std::string arg = __argv[i];
        if (arg == "--decompile-exe" && i + 1 < __argc)
        {
            std::string exePath = __argv[i + 1];
            std::string outFile = (i + 2 < __argc) ? __argv[i + 2] : "kyv_decompile_report.md";

            AttachConsole(ATTACH_PARENT_PROCESS);
            freopen("CONOUT$", "w", stdout);
            printf("[+] KYV Headless Engine: Launching and decompiling '%s'...\n", exePath.c_str());

            STARTUPINFOA si = { sizeof(si) };
            PROCESS_INFORMATION pi = {};
            std::string cmd = "\"" + exePath + "\" --daemon";
            if (CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            {
                Sleep(1200);
                kyv::Application app;
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
        else if (arg == "--decompile-pid" && i + 1 < __argc)
        {
            DWORD targetPid = (DWORD)atoi(__argv[i + 1]);
            std::string outFile = (i + 2 < __argc) ? __argv[i + 2] : "kyv_decompile_report.md";

            AttachConsole(ATTACH_PARENT_PROCESS);
            freopen("CONOUT$", "w", stdout);
            printf("[+] KYV Headless Engine: Starting IDA Pro automated decompilation on PID %lu...\n", targetPid);

            kyv::Application app;
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
        else if (arg == "--cli" || arg == "-c" || arg == "--repl")
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            if (hOut == INVALID_HANDLE_VALUE || hOut == nullptr)
            {
                AllocConsole();
            }
            freopen("CONIN$", "r", stdin);
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);

            kyv::Application app;
            kyv::CLIRepl repl;
            bool switchToGui = repl.Run(app);
            if (!switchToGui)
            {
                return 0;
            }
            // If user typed 'gui' in REPL, we break and continue to launch ImGui DX11 window!
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
        L"KYV - Memory Analysis & Reverse Engineering",
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

    // Create application
    kyv::Application app;
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
    bool runGui = false;
    bool runDecompile = false;
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--gui" || arg == "-g")
        {
            runGui = true;
            break;
        }
        else if (arg == "--decompile-exe" || arg == "--decompile-pid")
        {
            runDecompile = true;
            break;
        }
    }

    // Run OpenReverse Interactive CLI REPL by default or when requested
    if (!runGui && !runDecompile)
    {
        kyv::Application app;
        kyv::CLIRepl repl;
        bool switchToGui = repl.Run(app);
        if (!switchToGui)
        {
            return 0;
        }
    }

    return WinMain(GetModuleHandleW(nullptr), nullptr, GetCommandLineA(), SW_SHOWDEFAULT);
}
