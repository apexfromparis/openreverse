#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <string.h>

#define ID_OPEN 1001
#define ID_ANALYZE 1002
#define ID_AI 1003
#define ID_NAV_GRAPH 1004
#define ID_NAV_DISASM 1005
#define ID_NAV_STRINGS 1006
#define ID_NAV_IMPORTS 1007

static COLORREF bg = RGB(13, 16, 23);
static COLORREF panel = RGB(19, 23, 32);
static COLORREF panel2 = RGB(24, 29, 40);
static COLORREF border = RGB(43, 51, 67);
static COLORREF text = RGB(225, 231, 240);
static COLORREF muted = RGB(136, 148, 168);
static COLORREF cyan = RGB(78, 214, 196);
static COLORREF purple = RGB(154, 125, 255);
static HFONT font_ui, font_small, font_code, font_title;
static int active_nav = ID_NAV_DISASM;
static BOOL ai_open = TRUE;
static char loaded_file[MAX_PATH] = "No binary loaded";
static char status_text[128] = "Ready for analysis";

static void fill_rect(HDC dc, COLORREF color, int l, int t, int r, int b) {
    HBRUSH brush = CreateSolidBrush(color);
    RECT rect = {l, t, r, b};
    FillRect(dc, &rect, brush);
    DeleteObject(brush);
}

static void line(HDC dc, COLORREF color, int x1, int y1, int x2, int y2) {
    HPEN pen = CreatePen(PS_SOLID, 1, color);
    HPEN old = SelectObject(dc, pen);
    MoveToEx(dc, x1, y1, NULL); LineTo(dc, x2, y2);
    SelectObject(dc, old); DeleteObject(pen);
}

static void label(HDC dc, const char *value, int x, int y, COLORREF color, HFONT f) {
    SetTextColor(dc, color); SetBkMode(dc, TRANSPARENT);
    HFONT old = SelectObject(dc, f);
    TextOutA(dc, x, y, value, (int)strlen(value));
    SelectObject(dc, old);
}

static void rounded(HDC dc, COLORREF color, int l, int t, int r, int b, int radius) {
    HBRUSH brush = CreateSolidBrush(color);
    HBRUSH old = SelectObject(dc, brush);
    RoundRect(dc, l, t, r, b, radius, radius);
    SelectObject(dc, old); DeleteObject(brush);
}

static void draw_nav_item(HDC dc, const char *name, const char *glyph, int id, int y) {
    if (active_nav == id) {
        rounded(dc, RGB(31, 47, 58), 14, y, 225, y + 38, 7);
        fill_rect(dc, cyan, 14, y + 7, 17, y + 31);
    }
    label(dc, glyph, 31, y + 9, active_nav == id ? cyan : muted, font_ui);
    label(dc, name, 61, y + 10, active_nav == id ? text : muted, font_ui);
}

static void draw_app(HDC dc, int width, int height) {
    fill_rect(dc, bg, 0, 0, width, height);
    fill_rect(dc, panel, 0, 0, 240, height);
    line(dc, border, 240, 0, 240, height);

    label(dc, "P", 26, 24, cyan, font_title);
    label(dc, "POWERFULL", 56, 25, text, font_title);
    label(dc, "IDA  /  REVERSAL WORKBENCH", 57, 51, muted, font_small);
    line(dc, border, 24, 78, 216, 78);
    label(dc, "WORKSPACE", 25, 99, muted, font_small);
    draw_nav_item(dc, "Disassembly", "<>", ID_NAV_DISASM, 118);
    draw_nav_item(dc, "Control Flow", "o", ID_NAV_GRAPH, 160);
    draw_nav_item(dc, "Strings", "#", ID_NAV_STRINGS, 202);
    draw_nav_item(dc, "Imports", "<>", ID_NAV_IMPORTS, 244);
    label(dc, "EXTENSIONS", 25, 310, muted, font_small);
    rounded(dc, RGB(30, 35, 47), 24, 335, 216, 376, 7);
    label(dc, "+", 38, 344, purple, font_ui);
    label(dc, "Plugin manager", 61, 346, text, font_ui);
    label(dc, "3 active plugins", 61, 364, muted, font_small);
    label(dc, "SYSTEM", 25, height - 100, muted, font_small);
    label(dc, "v0.1.0  /  LOCAL BUILD", 25, height - 76, muted, font_small);
    label(dc, "●  Engine online", 25, height - 49, cyan, font_small);

    fill_rect(dc, panel, 241, 0, width, 64);
    line(dc, border, 241, 63, width, 63);
    label(dc, "PROJECT /", 267, 23, muted, font_small);
    label(dc, loaded_file, 341, 20, text, font_ui);
    rounded(dc, RGB(34, 41, 54), width - 210, 15, width - 120, 47, 6);
    label(dc, "RUN", width - 184, 23, cyan, font_small);
    rounded(dc, cyan, width - 108, 15, width - 24, 47, 6);
    label(dc, "OPEN BINARY", width - 97, 23, RGB(9, 25, 26), font_small);

    int content_right = ai_open ? width - 315 : width - 24;
    label(dc, "DISASSEMBLY", 267, 91, text, font_title);
    label(dc, "x64  |  IDA-like analysis view", 267, 119, muted, font_small);
    rounded(dc, RGB(25, 31, 42), content_right - 150, 84, content_right, 119, 5);
    label(dc, "ANALYZE", content_right - 128, 94, cyan, font_small);
    line(dc, border, 267, 142, content_right, 142);

    int code_top = 163;
    const char *rows[][4] = {
        {"00401000", "push", "rbp", "; entry_point"},
        {"00401001", "mov", "rbp, rsp", ""},
        {"00401004", "sub", "rsp, 30h", "; stack frame"},
        {"00401008", "lea", "rcx, aPowerfullI", "; \"Powerfull IDA\""},
        {"0040100F", "call", "sub_401250", "; init_engine"},
        {"00401014", "test", "eax, eax", ""},
        {"00401016", "jz", "short loc_40102A", "; error path"},
        {"00401018", "mov", "[rbp+plugin_count], 3", ""},
        {"00401022", "call", "ai::load_model", "; AI assistant ready"},
        {"00401027", "jmp", "short loc_401040", ""}
    };
    for (int i = 0; i < 10; i++) {
        int y = code_top + i * 27;
        label(dc, rows[i][0], 267, y, muted, font_code);
        label(dc, rows[i][1], 365, y, purple, font_code);
        label(dc, rows[i][2], 445, y, text, font_code);
        label(dc, rows[i][3], 660, y, i == 8 ? cyan : muted, font_code);
    }
    line(dc, border, 267, 455, content_right, 455);
    label(dc, "FUNCTIONS", 267, 473, muted, font_small);
    label(dc, "sub_401000", 267, 501, cyan, font_code);
    label(dc, "sub_401250", 420, 501, text, font_code);
    label(dc, "ai::load_model", 575, 501, purple, font_code);

    int console_y = height - 145;
    fill_rect(dc, RGB(16, 20, 28), 241, console_y, content_right + 1, height);
    line(dc, border, 241, console_y, content_right, console_y);
    label(dc, "CONSOLE", 267, console_y + 16, muted, font_small);
    label(dc, ">  engine: waiting for binary input", 267, console_y + 45, cyan, font_code);
    label(dc, ">  ai: model endpoint ready / local mode", 267, console_y + 70, muted, font_code);
    label(dc, status_text, 267, console_y + 95, text, font_code);

    if (ai_open) {
        fill_rect(dc, panel, width - 300, 64, width, height);
        line(dc, border, width - 300, 64, width - 300, height);
        label(dc, "AI COPILOT", width - 275, 92, text, font_title);
        rounded(dc, RGB(37, 32, 64), width - 275, 124, width - 49, 155, 6);
        label(dc, "●  ONLINE", width - 258, 133, purple, font_small);
        label(dc, "Ask about this function...", width - 260, 181, muted, font_small);
        line(dc, border, width - 275, 205, width - 49, 205);
        label(dc, "SUGGESTIONS", width - 275, 226, muted, font_small);
        label(dc, "Explain selected function", width - 260, 257, text, font_small);
        label(dc, "Find dangerous calls", width - 260, 289, text, font_small);
        label(dc, "Rename local variables", width - 260, 321, text, font_small);
        line(dc, border, width - 275, 348, width - 49, 348);
        label(dc, "PLUGINS", width - 275, 370, muted, font_small);
        label(dc, "AI Decompiler", width - 260, 402, cyan, font_small);
        label(dc, "Pattern Hunter", width - 260, 430, cyan, font_small);
        label(dc, "Hex Exporter", width - 260, 458, cyan, font_small);
    }
}

static void open_binary(HWND hwnd) {
    OPENFILENAMEA ofn = {0}; char file[MAX_PATH] = {0};
    ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = hwnd; ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH; ofn.lpstrFilter = "Binary files\0*.exe;*.dll;*.bin;*.elf\0All files\0*.*\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameA(&ofn)) {
        const char *slash = strrchr(file, '\\');
        strncpy(loaded_file, slash ? slash + 1 : file, sizeof(loaded_file) - 1);
        strncpy(status_text, "Loaded binary. Analysis queued.", sizeof(status_text) - 1);
        InvalidateRect(hwnd, NULL, FALSE);
    }
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: return 0;
    case WM_LBUTTONDOWN: {
        int x = LOWORD(lp), y = HIWORD(lp); RECT r; GetClientRect(hwnd, &r);
        if (x > r.right - 125 && y < 65) { open_binary(hwnd); return 0; }
        if (x > 240 && y > 80 && x < r.right - 315 && y < 130) {
            strncpy(status_text, "Analysis complete. 3 functions identified.", sizeof(status_text) - 1);
            InvalidateRect(hwnd, NULL, FALSE); return 0;
        }
        if (x < 240) {
            if (y >= 118 && y < 158) active_nav = ID_NAV_DISASM;
            else if (y >= 160 && y < 200) active_nav = ID_NAV_GRAPH;
            else if (y >= 202 && y < 242) active_nav = ID_NAV_STRINGS;
            else if (y >= 244 && y < 284) active_nav = ID_NAV_IMPORTS;
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    }
    case WM_KEYDOWN: if (wp == VK_F1) { ai_open = !ai_open; InvalidateRect(hwnd, NULL, FALSE); } return 0;
    case WM_SIZE: InvalidateRect(hwnd, NULL, FALSE); return 0;
    case WM_PAINT: { PAINTSTRUCT ps; HDC dc = BeginPaint(hwnd, &ps); RECT r; GetClientRect(hwnd, &r); draw_app(dc, r.right, r.bottom); EndPaint(hwnd, &ps); return 0; }
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE unused, LPSTR command, int show) {
    (void)unused; (void)command;
    font_ui = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
    font_small = CreateFontA(11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
    font_title = CreateFontA(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
    font_code = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, DEFAULT_QUALITY, FIXED_PITCH, "Consolas");
    WNDCLASSA wc = {0}; wc.hInstance = instance; wc.lpfnWndProc = window_proc; wc.lpszClassName = "PowerfullIDA";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = CreateSolidBrush(bg);
    RegisterClassA(&wc);
    HWND hwnd = CreateWindowExA(0, wc.lpszClassName, "Powerfull IDA - Reversal Workbench", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 1320, 820, NULL, NULL, instance, NULL);
    ShowWindow(hwnd, show); UpdateWindow(hwnd);
    MSG msg; while (GetMessageA(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageA(&msg); }
    DeleteObject(font_ui); DeleteObject(font_small); DeleteObject(font_title); DeleteObject(font_code);
    return (int)msg.wParam;
}
