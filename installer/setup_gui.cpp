// ============================================================================
// OpenReverse Studio v2.0 - Official Windows Setup Wizard (Win32 Native)
// Professional, ultra-clean software installer (Visual Studio / NSIS style)
// ============================================================================

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <objbase.h>
#include <dwmapi.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")

// Enable Visual Styles (Comctl32 v6)
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Control IDs
#define IDC_HEADER_TITLE    1001
#define IDC_HEADER_SUB      1002
#define IDC_BODY_TEXT       1003
#define IDC_DEST_LABEL      1004
#define IDC_DEST_PATH       1005
#define IDC_CHK_DESKTOP     1006
#define IDC_CHK_STARTMENU   1007
#define IDC_CHK_REGISTRY    1008
#define IDC_CHK_RUNNOW      1009
#define IDC_PROGRESS        1010
#define IDC_LOG_TEXT        1011
#define IDC_BTN_INSTALL     1012
#define IDC_BTN_CANCEL      1013

enum class SetupPage
{
    Welcome,
    Installing,
    Complete,
    UninstallConfirm,
    Uninstalling,
    UninstallComplete
};

struct WizardContext
{
    SetupPage page = SetupPage::Welcome;
    bool isUninstall = false;

    // Controls
    HWND hwndTitle = nullptr;
    HWND hwndSub = nullptr;
    HWND hwndBody = nullptr;
    HWND hwndDestLabel = nullptr;
    HWND hwndDestPath = nullptr;
    HWND hwndChkDesktop = nullptr;
    HWND hwndChkStartMenu = nullptr;
    HWND hwndChkRegistry = nullptr;
    HWND hwndChkRunNow = nullptr;
    HWND hwndProgress = nullptr;
    HWND hwndLog = nullptr;
    HWND hwndBtnInstall = nullptr;
    HWND hwndBtnCancel = nullptr;

    // Fonts & Brushes
    HFONT hFontNormal = nullptr;
    HFONT hFontBold = nullptr;
    HBRUSH hBrushBg = nullptr;
    HBRUSH hBrushEdit = nullptr;

    // Installation State
    int step = 0;
    std::string programsDir;
    std::string installDir;
    std::string targetExe;
};

static WizardContext g_ctx;

// ─── Windows Shell COM Shortcut Helper ───────────────────────────────────────
static bool CreateShortcut(const std::wstring& targetPath,
                           const std::wstring& workingDir,
                           const std::wstring& shortcutPath,
                           const std::wstring& description)
{
    CoInitialize(NULL);
    IShellLinkW* psl = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&psl);
    if (SUCCEEDED(hr))
    {
        psl->SetPath(targetPath.c_str());
        psl->SetWorkingDirectory(workingDir.c_str());
        psl->SetDescription(description.c_str());
        psl->SetIconLocation(targetPath.c_str(), 0);

        IPersistFile* ppf = nullptr;
        hr = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);
        if (SUCCEEDED(hr))
        {
            hr = ppf->Save(shortcutPath.c_str(), TRUE);
            ppf->Release();
        }
        psl->Release();
    }
    CoUninitialize();
    return SUCCEEDED(hr);
}

static void AppendLog(const std::wstring& line)
{
    int len = GetWindowTextLengthW(g_ctx.hwndLog);
    SendMessageW(g_ctx.hwndLog, EM_SETSEL, len, len);
    std::wstring text = line + L"\r\n";
    SendMessageW(g_ctx.hwndLog, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
    SendMessageW(g_ctx.hwndLog, EM_SCROLLCARET, 0, 0);
}

static void UpdatePageVisibility()
{
    // Hide all intermediate/state-dependent controls first
    ShowWindow(g_ctx.hwndDestLabel, SW_HIDE);
    ShowWindow(g_ctx.hwndDestPath, SW_HIDE);
    ShowWindow(g_ctx.hwndChkDesktop, SW_HIDE);
    ShowWindow(g_ctx.hwndChkStartMenu, SW_HIDE);
    ShowWindow(g_ctx.hwndChkRegistry, SW_HIDE);
    ShowWindow(g_ctx.hwndChkRunNow, SW_HIDE);
    ShowWindow(g_ctx.hwndProgress, SW_HIDE);
    ShowWindow(g_ctx.hwndLog, SW_HIDE);

    if (g_ctx.page == SetupPage::Welcome)
    {
        SetWindowTextW(g_ctx.hwndTitle, L"Welcome to OpenReverse Studio Setup");
        SetWindowTextW(g_ctx.hwndSub, L"OpenReverse Studio 2.0.0");
        SetWindowTextW(g_ctx.hwndBody,
            L"Setup will install OpenReverse Studio 2.0.0 on your computer.\r\n\r\n"
            L"It is recommended that you close all other applications before starting Setup. "
            L"This will make it possible to update relevant system files without having to reboot your computer.\r\n\r\n"
            L"Click Install to continue, or Cancel to exit Setup.");

        ShowWindow(g_ctx.hwndDestLabel, SW_SHOW);
        ShowWindow(g_ctx.hwndDestPath, SW_SHOW);
        ShowWindow(g_ctx.hwndChkDesktop, SW_SHOW);
        ShowWindow(g_ctx.hwndChkStartMenu, SW_SHOW);
        ShowWindow(g_ctx.hwndChkRegistry, SW_SHOW);

        SetWindowTextW(g_ctx.hwndBtnInstall, L"Install");
        EnableWindow(g_ctx.hwndBtnCancel, TRUE);
    }
    else if (g_ctx.page == SetupPage::Installing || g_ctx.page == SetupPage::Uninstalling)
    {
        SetWindowTextW(g_ctx.hwndTitle, g_ctx.page == SetupPage::Installing ? L"Installing OpenReverse Studio" : L"Uninstalling OpenReverse Studio");
        SetWindowTextW(g_ctx.hwndSub, g_ctx.page == SetupPage::Installing ? L"Please wait while OpenReverse Studio is being installed." : L"Please wait while files are being removed.");
        SetWindowTextW(g_ctx.hwndBody, L"");

        ShowWindow(g_ctx.hwndProgress, SW_SHOW);
        ShowWindow(g_ctx.hwndLog, SW_SHOW);

        EnableWindow(g_ctx.hwndBtnInstall, FALSE);
        EnableWindow(g_ctx.hwndBtnCancel, FALSE);
    }
    else if (g_ctx.page == SetupPage::Complete)
    {
        SetWindowTextW(g_ctx.hwndTitle, L"Completing OpenReverse Studio Setup");
        SetWindowTextW(g_ctx.hwndSub, L"OpenReverse Studio 2.0.0");
        SetWindowTextW(g_ctx.hwndBody,
            L"OpenReverse Studio 2.0.0 has been installed on your computer.\r\n\r\n"
            L"Click Finish to close Setup.");

        ShowWindow(g_ctx.hwndChkRunNow, SW_SHOW);

        SetWindowTextW(g_ctx.hwndBtnInstall, L"Finish");
        EnableWindow(g_ctx.hwndBtnInstall, TRUE);
        EnableWindow(g_ctx.hwndBtnCancel, FALSE);
    }
    else if (g_ctx.page == SetupPage::UninstallConfirm)
    {
        SetWindowTextW(g_ctx.hwndTitle, L"OpenReverse Studio Uninstaller");
        SetWindowTextW(g_ctx.hwndSub, L"OpenReverse Studio 2.0.0");
        SetWindowTextW(g_ctx.hwndBody,
            L"Are you sure you want to completely remove OpenReverse Studio and all of its components?\r\n\r\n"
            L"This will remove the application binary, Desktop and Start Menu shortcuts, and registry entries.");

        SetWindowTextW(g_ctx.hwndBtnInstall, L"Uninstall");
        EnableWindow(g_ctx.hwndBtnCancel, TRUE);
    }
    else if (g_ctx.page == SetupPage::UninstallComplete)
    {
        SetWindowTextW(g_ctx.hwndTitle, L"Uninstallation Complete");
        SetWindowTextW(g_ctx.hwndSub, L"OpenReverse Studio 2.0.0");
        SetWindowTextW(g_ctx.hwndBody,
            L"OpenReverse Studio was successfully removed from your computer.\r\n\r\n"
            L"Click Finish to exit Setup.");

        SetWindowTextW(g_ctx.hwndBtnInstall, L"Finish");
        EnableWindow(g_ctx.hwndBtnInstall, TRUE);
        EnableWindow(g_ctx.hwndBtnCancel, FALSE);
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        // Dark theme brushes
        g_ctx.hBrushBg = CreateSolidBrush(RGB(30, 30, 30));       // #1E1E1E
        g_ctx.hBrushEdit = CreateSolidBrush(RGB(20, 20, 20));     // #141414

        // Standard fonts
        g_ctx.hFontNormal = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_ctx.hFontBold = CreateFontW(22, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        // Top Header
        g_ctx.hwndTitle = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            24, 20, 480, 28, hwnd, (HMENU)IDC_HEADER_TITLE, nullptr, nullptr);
        SendMessageW(g_ctx.hwndTitle, WM_SETFONT, (WPARAM)g_ctx.hFontBold, TRUE);

        g_ctx.hwndSub = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            24, 50, 480, 20, hwnd, (HMENU)IDC_HEADER_SUB, nullptr, nullptr);
        SendMessageW(g_ctx.hwndSub, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

        // Body Text
        g_ctx.hwndBody = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            24, 85, 480, 110, hwnd, (HMENU)IDC_BODY_TEXT, nullptr, nullptr);
        SendMessageW(g_ctx.hwndBody, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

        // Destination Folder Section
        g_ctx.hwndDestLabel = CreateWindowW(L"STATIC", L"Destination Folder:", WS_CHILD,
            24, 195, 200, 20, hwnd, (HMENU)IDC_DEST_LABEL, nullptr, nullptr);
        SendMessageW(g_ctx.hwndDestLabel, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

        WCHAR wInstallDir[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, g_ctx.installDir.c_str(), -1, wInstallDir, MAX_PATH);
        g_ctx.hwndDestPath = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", wInstallDir,
            WS_CHILD | ES_AUTOHSCROLL | ES_READONLY,
            24, 218, 460, 24, hwnd, (HMENU)IDC_DEST_PATH, nullptr, nullptr);
        SendMessageW(g_ctx.hwndDestPath, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

        // Checkboxes
        g_ctx.hwndChkDesktop = CreateWindowW(L"BUTTON", L"Create a desktop shortcut", WS_CHILD | BS_AUTOCHECKBOX,
            24, 255, 300, 20, hwnd, (HMENU)IDC_CHK_DESKTOP, nullptr, nullptr);
        SendMessageW(g_ctx.hwndChkDesktop, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);
        SendMessageW(g_ctx.hwndChkDesktop, BM_SETCHECK, BST_CHECKED, 0);

        g_ctx.hwndChkStartMenu = CreateWindowW(L"BUTTON", L"Create a Start Menu shortcut", WS_CHILD | BS_AUTOCHECKBOX,
            24, 280, 300, 20, hwnd, (HMENU)IDC_CHK_STARTMENU, nullptr, nullptr);
        SendMessageW(g_ctx.hwndChkStartMenu, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);
        SendMessageW(g_ctx.hwndChkStartMenu, BM_SETCHECK, BST_CHECKED, 0);

        g_ctx.hwndChkRegistry = CreateWindowW(L"BUTTON", L"Register in Windows Add/Remove Programs", WS_CHILD | BS_AUTOCHECKBOX,
            24, 305, 300, 20, hwnd, (HMENU)IDC_CHK_REGISTRY, nullptr, nullptr);
        SendMessageW(g_ctx.hwndChkRegistry, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);
        SendMessageW(g_ctx.hwndChkRegistry, BM_SETCHECK, BST_CHECKED, 0);

        g_ctx.hwndChkRunNow = CreateWindowW(L"BUTTON", L"Run OpenReverse Studio now", WS_CHILD | BS_AUTOCHECKBOX,
            24, 200, 300, 20, hwnd, (HMENU)IDC_CHK_RUNNOW, nullptr, nullptr);
        SendMessageW(g_ctx.hwndChkRunNow, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);
        SendMessageW(g_ctx.hwndChkRunNow, BM_SETCHECK, BST_CHECKED, 0);

        // Progress Bar
        g_ctx.hwndProgress = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
            WS_CHILD | PBS_SMOOTH,
            24, 90, 470, 22, hwnd, (HMENU)IDC_PROGRESS, nullptr, nullptr);
        SendMessageW(g_ctx.hwndProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

        // Activity Log Box
        g_ctx.hwndLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
            24, 125, 470, 185, hwnd, (HMENU)IDC_LOG_TEXT, nullptr, nullptr);
        SendMessageW(g_ctx.hwndLog, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

        // Buttons
        g_ctx.hwndBtnInstall = CreateWindowW(L"BUTTON", L"Install", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            300, 335, 95, 28, hwnd, (HMENU)IDC_BTN_INSTALL, nullptr, nullptr);
        SendMessageW(g_ctx.hwndBtnInstall, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

        g_ctx.hwndBtnCancel = CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            405, 335, 85, 28, hwnd, (HMENU)IDC_BTN_CANCEL, nullptr, nullptr);
        SendMessageW(g_ctx.hwndBtnCancel, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

        UpdatePageVisibility();
        break;
    }
    case WM_TIMER:
    {
        if (wParam == 1) // Install sequence
        {
            g_ctx.step++;
            if (g_ctx.step == 1)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 15, 0);
                AppendLog(L"Create folder: " + std::wstring(g_ctx.installDir.begin(), g_ctx.installDir.end()));
                CreateDirectoryA(g_ctx.programsDir.c_str(), nullptr);
                CreateDirectoryA(g_ctx.installDir.c_str(), nullptr);
            }
            else if (g_ctx.step == 2)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 45, 0);
                AppendLog(L"Extract: openreverse-gui.exe...");
                HRSRC hRes = FindResourceW(GetModuleHandle(nullptr), MAKEINTRESOURCEW(101), RT_RCDATA);
                if (hRes)
                {
                    HGLOBAL hMem = LoadResource(GetModuleHandle(nullptr), hRes);
                    DWORD resSize = SizeofResource(GetModuleHandle(nullptr), hRes);
                    void* pData = LockResource(hMem);
                    if (pData && resSize > 0)
                    {
                        HANDLE hFile = CreateFileA(g_ctx.targetExe.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                        if (hFile != INVALID_HANDLE_VALUE)
                        {
                            DWORD written = 0;
                            WriteFile(hFile, pData, resSize, &written, nullptr);
                            CloseHandle(hFile);
                        }
                    }
                }
            }
            else if (g_ctx.step == 3)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 75, 0);
                WCHAR wInstallDir[MAX_PATH];
                WCHAR wTargetExe[MAX_PATH];
                MultiByteToWideChar(CP_UTF8, 0, g_ctx.installDir.c_str(), -1, wInstallDir, MAX_PATH);
                MultiByteToWideChar(CP_UTF8, 0, g_ctx.targetExe.c_str(), -1, wTargetExe, MAX_PATH);

                if (SendMessageW(g_ctx.hwndChkDesktop, BM_GETCHECK, 0, 0) == BST_CHECKED)
                {
                    char desktopPath[MAX_PATH];
                    if (SHGetFolderPathA(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, SHGFP_TYPE_CURRENT, desktopPath) == S_OK)
                    {
                        std::string lnk = std::string(desktopPath) + "\\OpenReverse Studio.lnk";
                        WCHAR wLnk[MAX_PATH];
                        MultiByteToWideChar(CP_UTF8, 0, lnk.c_str(), -1, wLnk, MAX_PATH);
                        CreateShortcut(wTargetExe, wInstallDir, wLnk, L"OpenReverse Studio 2.0.0");
                        AppendLog(L"Create shortcut: Desktop\\OpenReverse Studio.lnk");
                    }
                }
                if (SendMessageW(g_ctx.hwndChkStartMenu, BM_GETCHECK, 0, 0) == BST_CHECKED)
                {
                    char startMenuPath[MAX_PATH];
                    if (SHGetFolderPathA(nullptr, CSIDL_PROGRAMS, nullptr, SHGFP_TYPE_CURRENT, startMenuPath) == S_OK)
                    {
                        std::string lnk = std::string(startMenuPath) + "\\OpenReverse Studio.lnk";
                        WCHAR wLnk[MAX_PATH];
                        MultiByteToWideChar(CP_UTF8, 0, lnk.c_str(), -1, wLnk, MAX_PATH);
                        CreateShortcut(wTargetExe, wInstallDir, wLnk, L"OpenReverse Studio 2.0.0");
                        AppendLog(L"Create shortcut: Start Menu\\OpenReverse Studio.lnk");
                    }
                }
            }
            else if (g_ctx.step == 4)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 95, 0);
                if (SendMessageW(g_ctx.hwndChkRegistry, BM_GETCHECK, 0, 0) == BST_CHECKED)
                {
                    HKEY hKey;
                    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OpenReverseStudio",
                        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
                    {
                        RegSetValueExA(hKey, "DisplayName", 0, REG_SZ, (const BYTE*)"OpenReverse Studio", 19);
                        RegSetValueExA(hKey, "DisplayVersion", 0, REG_SZ, (const BYTE*)"2.0.0", 6);
                        RegSetValueExA(hKey, "Publisher", 0, REG_SZ, (const BYTE*)"OpenReverse Community", 22);
                        RegSetValueExA(hKey, "InstallLocation", 0, REG_SZ, (const BYTE*)g_ctx.installDir.c_str(), (DWORD)g_ctx.installDir.size() + 1);
                        RegSetValueExA(hKey, "DisplayIcon", 0, REG_SZ, (const BYTE*)g_ctx.targetExe.c_str(), (DWORD)g_ctx.targetExe.size() + 1);
                        std::string uninstCmd = "\"" + g_ctx.targetExe + "\" --uninstall";
                        RegSetValueExA(hKey, "UninstallString", 0, REG_SZ, (const BYTE*)uninstCmd.c_str(), (DWORD)uninstCmd.size() + 1);
                        RegCloseKey(hKey);
                        AppendLog(L"Write registry: Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OpenReverseStudio");
                    }
                }
            }
            else if (g_ctx.step >= 5)
            {
                KillTimer(hwnd, 1);
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 100, 0);
                AppendLog(L"Completed successfully.");
                g_ctx.page = SetupPage::Complete;
                UpdatePageVisibility();
            }
        }
        else if (wParam == 2) // Uninstall sequence
        {
            g_ctx.step++;
            if (g_ctx.step == 1)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 35, 0);
                AppendLog(L"Delete shortcut: Desktop\\OpenReverse Studio.lnk");
                char desktopPath[MAX_PATH];
                if (SHGetFolderPathA(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, SHGFP_TYPE_CURRENT, desktopPath) == S_OK)
                    DeleteFileA((std::string(desktopPath) + "\\OpenReverse Studio.lnk").c_str());
            }
            else if (g_ctx.step == 2)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 70, 0);
                AppendLog(L"Delete shortcut: Start Menu\\OpenReverse Studio.lnk");
                char startMenuPath[MAX_PATH];
                if (SHGetFolderPathA(nullptr, CSIDL_PROGRAMS, nullptr, SHGFP_TYPE_CURRENT, startMenuPath) == S_OK)
                    DeleteFileA((std::string(startMenuPath) + "\\OpenReverse Studio.lnk").c_str());
            }
            else if (g_ctx.step == 3)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 90, 0);
                AppendLog(L"Delete registry key: Uninstall\\OpenReverseStudio");
                RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OpenReverseStudio");
            }
            else if (g_ctx.step >= 4)
            {
                KillTimer(hwnd, 2);
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 100, 0);
                AppendLog(L"Uninstallation completed successfully.");
                g_ctx.page = SetupPage::UninstallComplete;
                UpdatePageVisibility();
            }
        }
        break;
    }
    case WM_COMMAND:
    {
        if (LOWORD(wParam) == IDC_BTN_INSTALL)
        {
            if (g_ctx.page == SetupPage::Welcome)
            {
                g_ctx.page = SetupPage::Installing;
                UpdatePageVisibility();
                g_ctx.step = 0;
                SetTimer(hwnd, 1, 150, nullptr); // 150ms step delay for smooth visual feedback
            }
            else if (g_ctx.page == SetupPage::Complete)
            {
                if (SendMessageW(g_ctx.hwndChkRunNow, BM_GETCHECK, 0, 0) == BST_CHECKED)
                {
                    ShellExecuteA(nullptr, "open", g_ctx.targetExe.c_str(), nullptr, g_ctx.installDir.c_str(), SW_SHOW);
                }
                PostQuitMessage(0);
            }
            else if (g_ctx.page == SetupPage::UninstallConfirm)
            {
                g_ctx.page = SetupPage::Uninstalling;
                UpdatePageVisibility();
                g_ctx.step = 0;
                SetTimer(hwnd, 2, 200, nullptr);
            }
            else if (g_ctx.page == SetupPage::UninstallComplete)
            {
                PostQuitMessage(0);
            }
        }
        else if (LOWORD(wParam) == IDC_BTN_CANCEL)
        {
            PostQuitMessage(0);
        }
        break;
    }
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // Dark window background #1E1E1E
        FillRect(hdc, &ps.rcPaint, g_ctx.hBrushBg);

        // Bottom separator line (x=0, y=320, width=540)
        RECT rcLine = { 0, 320, 540, 321 };
        HBRUSH hLineBrush = CreateSolidBrush(RGB(50, 50, 50));
        FillRect(hdc, &rcLine, hLineBrush);
        DeleteObject(hLineBrush);

        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
    {
        HDC hdcStatic = (HDC)wParam;
        SetTextColor(hdcStatic, RGB(240, 240, 240));
        SetBkColor(hdcStatic, RGB(30, 30, 30));
        return (INT_PTR)g_ctx.hBrushBg;
    }
    case WM_CTLCOLOREDIT:
    {
        HDC hdcEdit = (HDC)wParam;
        SetTextColor(hdcEdit, RGB(220, 220, 220));
        SetBkColor(hdcEdit, RGB(20, 20, 20));
        return (INT_PTR)g_ctx.hBrushEdit;
    }
    case WM_DESTROY:
    {
        if (g_ctx.hFontNormal) DeleteObject(g_ctx.hFontNormal);
        if (g_ctx.hFontBold) DeleteObject(g_ctx.hFontBold);
        if (g_ctx.hBrushBg) DeleteObject(g_ctx.hBrushBg);
        if (g_ctx.hBrushEdit) DeleteObject(g_ctx.hBrushEdit);
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;
    (void)nCmdShow;

    std::string cmdLine = lpCmdLine ? lpCmdLine : "";
    g_ctx.isUninstall = (cmdLine.find("--uninstall") != std::string::npos || cmdLine.find("/uninstall") != std::string::npos);
    g_ctx.page = g_ctx.isUninstall ? SetupPage::UninstallConfirm : SetupPage::Welcome;

    char localAppData[MAX_PATH] = { 0 };
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppData);
    g_ctx.programsDir = std::string(localAppData) + "\\Programs";
    g_ctx.installDir = g_ctx.programsDir + "\\OpenReverse Studio";
    g_ctx.targetExe = g_ctx.installDir + "\\openreverse-gui.exe";

    InitCommonControls();

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(WNDCLASSEXW);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    wc.hIconSm       = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"OpenReverseSetupClass_Win32";
    RegisterClassExW(&wc);

    int winWidth = 530;
    int winHeight = 410;
    int posX = (GetSystemMetrics(SM_CXSCREEN) - winWidth) / 2;
    int posY = (GetSystemMetrics(SM_CYSCREEN) - winHeight) / 2;

    HWND hwnd = CreateWindowExW(
        0, wc.lpszClassName,
        g_ctx.isUninstall ? L"OpenReverse Studio Uninstaller" : L"OpenReverse Studio Setup",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        posX, posY, winWidth, winHeight,
        nullptr, nullptr, hInstance, nullptr);

    // Dark Mode Windows Title Bar
    BOOL darkMode = TRUE;
    DwmSetWindowAttribute(hwnd, 20, &darkMode, sizeof(darkMode));

    HICON hSetupIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    if (hSetupIcon)
    {
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hSetupIcon);
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hSetupIcon);
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!IsDialogMessage(hwnd, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    UnregisterClassW(wc.lpszClassName, hInstance);
    return (int)msg.wParam;
}
