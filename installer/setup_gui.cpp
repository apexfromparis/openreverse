#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <objbase.h>
#include <dwmapi.h>
#include "openreverse_version.h"

#include <string>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")

#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

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
    Failed,
    UninstallConfirm,
    Uninstalling,
    UninstallComplete
};

struct WizardContext
{
    SetupPage page = SetupPage::Welcome;
    bool isUninstall = false;

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

    HFONT hFontNormal = nullptr;
    HFONT hFontBold = nullptr;
    HBRUSH hBrushBg = nullptr;
    HBRUSH hBrushEdit = nullptr;

    int step = 0;
    std::string installDir;
    std::string targetExe;
    std::string uninstallerExe;
    std::wstring failureMessage;
    bool deleteSelfOnExit = false;
};

static WizardContext g_ctx;
static void UpdatePageVisibility();

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

static std::wstring Widen(const std::string& value)
{
    if (value.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (length <= 1) return {};
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), length);
    result.pop_back();
    return result;
}

static std::wstring VersionedProduct()
{
    return std::wstring(L"OpenReverse ") + openreverse::kVersionWide;
}

static bool WriteEmbeddedApplication()
{
    HMODULE module = GetModuleHandleW(nullptr);
    HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(101), RT_RCDATA);
    if (!resource) return false;

    HGLOBAL loaded = LoadResource(module, resource);
    const DWORD size = SizeofResource(module, resource);
    const void* data = loaded ? LockResource(loaded) : nullptr;
    if (!data || size == 0) return false;

    HANDLE file = CreateFileA(g_ctx.targetExe.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    const bool success = WriteFile(file, data, size, &written, nullptr) && written == size;
    CloseHandle(file);
    if (!success) DeleteFileA(g_ctx.targetExe.c_str());
    return success;
}

static bool CopyUninstaller()
{
    char source[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, source, MAX_PATH)) return false;
    if (_stricmp(source, g_ctx.uninstallerExe.c_str()) == 0) return true;
    return CopyFileA(source, g_ctx.uninstallerExe.c_str(), FALSE) != FALSE;
}

static bool SetRegistryString(HKEY key, const char* name, const std::string& value)
{
    return RegSetValueExA(key, name, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(value.c_str()),
        static_cast<DWORD>(value.size() + 1)) == ERROR_SUCCESS;
}

static void FailOperation(HWND hwnd, UINT timerId, const std::wstring& message)
{
    KillTimer(hwnd, timerId);
    g_ctx.failureMessage = message;
    AppendLog(L"Error: " + message);
    g_ctx.page = SetupPage::Failed;
    UpdatePageVisibility();
}

static void UpdatePageVisibility()
{
    const std::wstring product = VersionedProduct();

    ShowWindow(g_ctx.hwndDestLabel, SW_HIDE);
    ShowWindow(g_ctx.hwndDestPath, SW_HIDE);
    ShowWindow(g_ctx.hwndChkDesktop, SW_HIDE);
    ShowWindow(g_ctx.hwndChkStartMenu, SW_HIDE);
    ShowWindow(g_ctx.hwndChkRegistry, SW_HIDE);
    ShowWindow(g_ctx.hwndChkRunNow, SW_HIDE);
    ShowWindow(g_ctx.hwndProgress, SW_HIDE);
    ShowWindow(g_ctx.hwndLog, SW_HIDE);
    SetWindowPos(g_ctx.hwndLog, nullptr, 24, 125, 470, 185, SWP_NOZORDER);

    if (g_ctx.page == SetupPage::Welcome)
    {
        SetWindowTextW(g_ctx.hwndTitle, L"Welcome to OpenReverse Setup");
        SetWindowTextW(g_ctx.hwndSub, product.c_str());
        const std::wstring body = L"Setup will install " + product + L" on your computer.\r\n\r\n"
            L"It is recommended that you close all other applications before starting Setup. "
            L"This will make it possible to update relevant system files without having to reboot your computer.\r\n\r\n"
            L"Click Install to continue, or Cancel to exit Setup.";
        SetWindowTextW(g_ctx.hwndBody, body.c_str());

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
        SetWindowTextW(g_ctx.hwndTitle, g_ctx.page == SetupPage::Installing ? L"Installing OpenReverse" : L"Uninstalling OpenReverse");
        SetWindowTextW(g_ctx.hwndSub, g_ctx.page == SetupPage::Installing ? L"Please wait while OpenReverse is being installed." : L"Please wait while files are being removed.");
        SetWindowTextW(g_ctx.hwndBody, L"");

        ShowWindow(g_ctx.hwndProgress, SW_SHOW);
        ShowWindow(g_ctx.hwndLog, SW_SHOW);

        EnableWindow(g_ctx.hwndBtnInstall, FALSE);
        EnableWindow(g_ctx.hwndBtnCancel, FALSE);
    }
    else if (g_ctx.page == SetupPage::Complete)
    {
        SetWindowTextW(g_ctx.hwndTitle, L"Completing OpenReverse Setup");
        SetWindowTextW(g_ctx.hwndSub, product.c_str());
        const std::wstring body = product + L" has been installed on your computer.\r\n\r\n"
            L"Click Finish to close Setup.";
        SetWindowTextW(g_ctx.hwndBody, body.c_str());

        ShowWindow(g_ctx.hwndChkRunNow, SW_SHOW);

        SetWindowTextW(g_ctx.hwndBtnInstall, L"Finish");
        EnableWindow(g_ctx.hwndBtnInstall, TRUE);
        EnableWindow(g_ctx.hwndBtnCancel, FALSE);
    }
    else if (g_ctx.page == SetupPage::Failed)
    {
        SetWindowTextW(g_ctx.hwndTitle, L"OpenReverse Setup failed");
        SetWindowTextW(g_ctx.hwndSub, product.c_str());
        const std::wstring body = g_ctx.failureMessage + L"\r\n\r\nReview the activity log, then close Setup and try again.";
        SetWindowTextW(g_ctx.hwndBody, body.c_str());
        SetWindowPos(g_ctx.hwndLog, nullptr, 24, 205, 470, 105, SWP_NOZORDER);
        ShowWindow(g_ctx.hwndLog, SW_SHOW);
        SetWindowTextW(g_ctx.hwndBtnInstall, L"Close");
        EnableWindow(g_ctx.hwndBtnInstall, TRUE);
        EnableWindow(g_ctx.hwndBtnCancel, FALSE);
    }
    else if (g_ctx.page == SetupPage::UninstallConfirm)
    {
        SetWindowTextW(g_ctx.hwndTitle, L"OpenReverse Uninstaller");
        SetWindowTextW(g_ctx.hwndSub, product.c_str());
        SetWindowTextW(g_ctx.hwndBody,
            L"Are you sure you want to remove OpenReverse?\r\n\r\n"
            L"This will remove the application binary, Desktop and Start Menu shortcuts, and registry entries.");

        SetWindowTextW(g_ctx.hwndBtnInstall, L"Uninstall");
        EnableWindow(g_ctx.hwndBtnCancel, TRUE);
    }
    else if (g_ctx.page == SetupPage::UninstallComplete)
    {
        SetWindowTextW(g_ctx.hwndTitle, L"Uninstallation Complete");
        SetWindowTextW(g_ctx.hwndSub, product.c_str());
        SetWindowTextW(g_ctx.hwndBody,
            L"OpenReverse was successfully removed from your computer.\r\n\r\n"
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
        g_ctx.hBrushBg = CreateSolidBrush(RGB(30, 30, 30));
        g_ctx.hBrushEdit = CreateSolidBrush(RGB(20, 20, 20));

        g_ctx.hFontNormal = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        g_ctx.hFontBold = CreateFontW(22, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        g_ctx.hwndTitle = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            24, 20, 480, 28, hwnd, (HMENU)IDC_HEADER_TITLE, nullptr, nullptr);
        SendMessageW(g_ctx.hwndTitle, WM_SETFONT, (WPARAM)g_ctx.hFontBold, TRUE);

        g_ctx.hwndSub = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            24, 50, 480, 20, hwnd, (HMENU)IDC_HEADER_SUB, nullptr, nullptr);
        SendMessageW(g_ctx.hwndSub, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

        g_ctx.hwndBody = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            24, 85, 480, 110, hwnd, (HMENU)IDC_BODY_TEXT, nullptr, nullptr);
        SendMessageW(g_ctx.hwndBody, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

        g_ctx.hwndDestLabel = CreateWindowW(L"STATIC", L"Destination Folder:", WS_CHILD,
            24, 195, 200, 20, hwnd, (HMENU)IDC_DEST_LABEL, nullptr, nullptr);
        SendMessageW(g_ctx.hwndDestLabel, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

        WCHAR wInstallDir[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, g_ctx.installDir.c_str(), -1, wInstallDir, MAX_PATH);
        g_ctx.hwndDestPath = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", wInstallDir,
            WS_CHILD | ES_AUTOHSCROLL | ES_READONLY,
            24, 218, 460, 24, hwnd, (HMENU)IDC_DEST_PATH, nullptr, nullptr);
        SendMessageW(g_ctx.hwndDestPath, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

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

        g_ctx.hwndChkRunNow = CreateWindowW(L"BUTTON", L"Run OpenReverse now", WS_CHILD | BS_AUTOCHECKBOX,
            24, 200, 300, 20, hwnd, (HMENU)IDC_CHK_RUNNOW, nullptr, nullptr);
        SendMessageW(g_ctx.hwndChkRunNow, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);
        SendMessageW(g_ctx.hwndChkRunNow, BM_SETCHECK, BST_CHECKED, 0);

        g_ctx.hwndProgress = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
            WS_CHILD | PBS_SMOOTH,
            24, 90, 470, 22, hwnd, (HMENU)IDC_PROGRESS, nullptr, nullptr);
        SendMessageW(g_ctx.hwndProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

        g_ctx.hwndLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
            24, 125, 470, 185, hwnd, (HMENU)IDC_LOG_TEXT, nullptr, nullptr);
        SendMessageW(g_ctx.hwndLog, WM_SETFONT, (WPARAM)g_ctx.hFontNormal, TRUE);

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
        if (wParam == 1)
        {
            g_ctx.step++;
            if (g_ctx.step == 1)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 15, 0);
                AppendLog(L"Create folder: " + Widen(g_ctx.installDir));
                const int result = SHCreateDirectoryExA(nullptr, g_ctx.installDir.c_str(), nullptr);
                if (result != ERROR_SUCCESS && result != ERROR_FILE_EXISTS && result != ERROR_ALREADY_EXISTS)
                    FailOperation(hwnd, 1, L"The installation directory could not be created.");
                else
                {
                    const std::string extensionDirectory = g_ctx.installDir + "\\extensions";
                    const int extensionResult = SHCreateDirectoryExA(nullptr,
                        extensionDirectory.c_str(), nullptr);
                    if (extensionResult != ERROR_SUCCESS && extensionResult != ERROR_FILE_EXISTS &&
                        extensionResult != ERROR_ALREADY_EXISTS)
                        FailOperation(hwnd, 1, L"The extensions directory could not be created.");
                    else
                        AppendLog(L"Create folder: " + Widen(extensionDirectory));
                }
            }
            else if (g_ctx.step == 2)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 45, 0);
                AppendLog(L"Extract: OpenReverse.exe");
                if (!WriteEmbeddedApplication())
                {
                    FailOperation(hwnd, 1, L"OpenReverse.exe could not be extracted.");
                    break;
                }
                AppendLog(L"Install: Uninstall.exe");
                if (!CopyUninstaller())
                    FailOperation(hwnd, 1, L"The uninstaller could not be installed.");
            }
            else if (g_ctx.step == 3)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 75, 0);
                const std::wstring installDir = Widen(g_ctx.installDir);
                const std::wstring targetExe = Widen(g_ctx.targetExe);
                const std::wstring description = VersionedProduct();

                if (SendMessageW(g_ctx.hwndChkDesktop, BM_GETCHECK, 0, 0) == BST_CHECKED)
                {
                    char desktopPath[MAX_PATH];
                    if (SHGetFolderPathA(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, SHGFP_TYPE_CURRENT, desktopPath) == S_OK)
                    {
                        const std::wstring shortcut = Widen(std::string(desktopPath) + "\\OpenReverse.lnk");
                        if (!CreateShortcut(targetExe, installDir, shortcut, description))
                        {
                            FailOperation(hwnd, 1, L"The Desktop shortcut could not be created.");
                            break;
                        }
                        AppendLog(L"Create shortcut: Desktop\\OpenReverse.lnk");
                    }
                }
                if (SendMessageW(g_ctx.hwndChkStartMenu, BM_GETCHECK, 0, 0) == BST_CHECKED)
                {
                    char startMenuPath[MAX_PATH];
                    if (SHGetFolderPathA(nullptr, CSIDL_PROGRAMS, nullptr, SHGFP_TYPE_CURRENT, startMenuPath) == S_OK)
                    {
                        const std::wstring shortcut = Widen(std::string(startMenuPath) + "\\OpenReverse.lnk");
                        if (!CreateShortcut(targetExe, installDir, shortcut, description))
                        {
                            FailOperation(hwnd, 1, L"The Start Menu shortcut could not be created.");
                            break;
                        }
                        AppendLog(L"Create shortcut: Start Menu\\OpenReverse.lnk");
                    }
                }
            }
            else if (g_ctx.step == 4)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 95, 0);
                if (SendMessageW(g_ctx.hwndChkRegistry, BM_GETCHECK, 0, 0) == BST_CHECKED)
                {
                    HKEY hKey;
                    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OpenReverse",
                        0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
                    {
                        const std::string uninstallCommand = "\"" + g_ctx.uninstallerExe + "\" --uninstall";
                        const bool registered =
                            SetRegistryString(hKey, "DisplayName", "OpenReverse") &&
                            SetRegistryString(hKey, "DisplayVersion", openreverse::kVersion) &&
                            SetRegistryString(hKey, "Publisher", "OpenReverse Community") &&
                            SetRegistryString(hKey, "InstallLocation", g_ctx.installDir) &&
                            SetRegistryString(hKey, "DisplayIcon", g_ctx.targetExe) &&
                            SetRegistryString(hKey, "UninstallString", uninstallCommand);
                        RegCloseKey(hKey);
                        if (!registered)
                        {
                            FailOperation(hwnd, 1, L"OpenReverse could not be registered with Windows.");
                            break;
                        }
                        AppendLog(L"Write registry: Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OpenReverse");
                    }
                    else
                    {
                        FailOperation(hwnd, 1, L"The Windows uninstall registry key could not be created.");
                        break;
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
        else if (wParam == 2)
        {
            g_ctx.step++;
            if (g_ctx.step == 1)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 35, 0);
                AppendLog(L"Delete shortcut: Desktop\\OpenReverse.lnk");
                char desktopPath[MAX_PATH];
                if (SHGetFolderPathA(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, SHGFP_TYPE_CURRENT, desktopPath) == S_OK)
                    DeleteFileA((std::string(desktopPath) + "\\OpenReverse.lnk").c_str());
            }
            else if (g_ctx.step == 2)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 70, 0);
                AppendLog(L"Delete shortcut: Start Menu\\OpenReverse.lnk");
                char startMenuPath[MAX_PATH];
                if (SHGetFolderPathA(nullptr, CSIDL_PROGRAMS, nullptr, SHGFP_TYPE_CURRENT, startMenuPath) == S_OK)
                    DeleteFileA((std::string(startMenuPath) + "\\OpenReverse.lnk").c_str());
            }
            else if (g_ctx.step == 3)
            {
                SendMessageW(g_ctx.hwndProgress, PBM_SETPOS, 90, 0);
                AppendLog(L"Delete registry key: Uninstall\\OpenReverse");
                RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OpenReverse");
            }
            else if (g_ctx.step == 4)
            {
                AppendLog(L"Delete: OpenReverse.exe");
                if (!DeleteFileA(g_ctx.targetExe.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND)
                {
                    FailOperation(hwnd, 2, L"OpenReverse.exe is still in use and could not be removed.");
                    break;
                }

                char self[MAX_PATH] = {};
                GetModuleFileNameA(nullptr, self, MAX_PATH);
                if (_stricmp(self, g_ctx.uninstallerExe.c_str()) != 0)
                    DeleteFileA(g_ctx.uninstallerExe.c_str());
                if (!RemoveDirectoryA(g_ctx.installDir.c_str()))
                {
                    const DWORD error = GetLastError();
                    if (error == ERROR_DIR_NOT_EMPTY)
                        AppendLog(L"Retain installation directory: it contains user-created files.");
                    else if (error != ERROR_PATH_NOT_FOUND)
                    {
                        FailOperation(hwnd, 2, L"The installation directory could not be removed.");
                        break;
                    }
                }
            }
            else if (g_ctx.step >= 5)
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
                SetTimer(hwnd, 1, 150, nullptr);
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
            else if (g_ctx.page == SetupPage::UninstallComplete || g_ctx.page == SetupPage::Failed)
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

        FillRect(hdc, &ps.rcPaint, g_ctx.hBrushBg);

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
        if (g_ctx.deleteSelfOnExit)
        {
            wchar_t self[MAX_PATH] = {};
            if (GetModuleFileNameW(nullptr, self, MAX_PATH))
                MoveFileExW(self, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
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

    char localAppData[MAX_PATH] = { 0 };
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppData);
    g_ctx.installDir = std::string(localAppData) + "\\Programs\\OpenReverse";
    g_ctx.targetExe = g_ctx.installDir + "\\OpenReverse.exe";
    g_ctx.uninstallerExe = g_ctx.installDir + "\\Uninstall.exe";

    const std::string cmdLine = lpCmdLine ? lpCmdLine : "";
    g_ctx.isUninstall = cmdLine.find("--uninstall") != std::string::npos ||
        cmdLine.find("/uninstall") != std::string::npos;
    const bool fromTemporaryCopy = cmdLine.find("--from-temp") != std::string::npos;

    if (g_ctx.isUninstall && !fromTemporaryCopy)
    {
        char self[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, self, MAX_PATH);
        if (_stricmp(self, g_ctx.uninstallerExe.c_str()) == 0)
        {
            char tempDir[MAX_PATH] = {};
            GetTempPathA(MAX_PATH, tempDir);
            const std::string tempUninstaller = std::string(tempDir) +
                "OpenReverse-Uninstall-" + std::to_string(GetCurrentProcessId()) + ".exe";
            if (!CopyFileA(self, tempUninstaller.c_str(), FALSE) ||
                reinterpret_cast<INT_PTR>(ShellExecuteA(nullptr, "open", tempUninstaller.c_str(),
                    "--uninstall --from-temp", nullptr, SW_SHOW)) <= 32)
            {
                MessageBoxW(nullptr, L"The OpenReverse uninstaller could not be started.",
                    L"OpenReverse Uninstaller", MB_OK | MB_ICONERROR);
                return 1;
            }
            return 0;
        }
    }

    g_ctx.deleteSelfOnExit = g_ctx.isUninstall && fromTemporaryCopy;
    g_ctx.page = g_ctx.isUninstall ? SetupPage::UninstallConfirm : SetupPage::Welcome;

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
        g_ctx.isUninstall ? L"OpenReverse Uninstaller" : L"OpenReverse Setup",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        posX, posY, winWidth, winHeight,
        nullptr, nullptr, hInstance, nullptr);

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
