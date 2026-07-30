#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <string.h>

#define NAV_DISASM 1
#define NAV_GRAPH 2
#define NAV_STRINGS 3
#define NAV_IMPORTS 4

static const COLORREF C_BG = RGB(11, 14, 20);
static const COLORREF C_SIDEBAR = RGB(17, 21, 29);
static const COLORREF C_PANEL = RGB(20, 25, 35);
static const COLORREF C_PANEL_RAISED = RGB(26, 32, 44);
static const COLORREF C_BORDER = RGB(43, 52, 68);
static const COLORREF C_TEXT = RGB(231, 237, 245);
static const COLORREF C_MUTED = RGB(133, 148, 169);
static const COLORREF C_CYAN = RGB(70, 215, 193);
static const COLORREF C_PURPLE = RGB(164, 132, 255);
static const COLORREF C_ORANGE = RGB(245, 174, 91);

static HFONT f_ui, f_small, f_code, f_heading, f_brand;
static int active_nav = NAV_DISASM;
static int hover_target = 0;
static BOOL ai_open = TRUE;
static BOOL binary_loaded = FALSE;
static char loaded_file[MAX_PATH] = "No binary loaded";
static char status_text[160] = "Ready for analysis";

static void copy_text(char *dst, size_t capacity, const char *src) {
    if (capacity == 0) return;
    strncpy(dst, src, capacity - 1);
    dst[capacity - 1] = '\0';
}

static void rect_fill(HDC dc, COLORREF color, RECT r) {
    HBRUSH brush = CreateSolidBrush(color);
    FillRect(dc, &r, brush);
    DeleteObject(brush);
}

static void divider(HDC dc, int x1, int y1, int x2, int y2) {
    HPEN pen = CreatePen(PS_SOLID, 1, C_BORDER);
    HPEN old = (HPEN)SelectObject(dc, pen);
    MoveToEx(dc, x1, y1, NULL);
    LineTo(dc, x2, y2);
    SelectObject(dc, old);
    DeleteObject(pen);
}

static void text_at(HDC dc, const char *value, int x, int y, COLORREF color, HFONT font) {
    HFONT old = (HFONT)SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    TextOutA(dc, x, y, value, (int)strlen(value));
    SelectObject(dc, old);
}

static void text_clipped(HDC dc, const char *value, RECT r, COLORREF color, HFONT font) {
    HFONT old = (HFONT)SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    DrawTextA(dc, value, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    SelectObject(dc, old);
}

static void rounded_box(HDC dc, COLORREF color, RECT r, int radius) {
    HBRUSH brush = CreateSolidBrush(color);
    HBRUSH old = (HBRUSH)SelectObject(dc, brush);
    RoundRect(dc, r.left, r.top, r.right, r.bottom, radius, radius);
    SelectObject(dc, old);
    DeleteObject(brush);
}

static BOOL point_in(POINT p, RECT r) {
    return p.x >= r.left && p.x < r.right && p.y >= r.top && p.y < r.bottom;
}

static RECT make_rect(int left, int top, int right, int bottom) {
    RECT r = {left, top, right, bottom};
    return r;
}

static void draw_button(HDC dc, RECT r, const char *caption, BOOL primary, BOOL hovered) {
    COLORREF fill = primary ? C_CYAN : (hovered ? C_PANEL_RAISED : RGB(31, 38, 51));
    COLORREF ink = primary ? RGB(8, 23, 24) : (hovered ? C_TEXT : C_MUTED);
    rounded_box(dc, fill, r, 7);
    text_clipped(dc, caption, make_rect(r.left + 10, r.top, r.right - 10, r.bottom), ink, f_small);
}

static void draw_nav_item(HDC dc, RECT r, const char *glyph, const char *title, int id, BOOL hovered) {
    BOOL active = active_nav == id;
    if (active) {
        rounded_box(dc, RGB(28, 53, 58), r, 7);
        rect_fill(dc, C_CYAN, make_rect(r.left, r.top + 7, r.left + 3, r.bottom - 7));
    } else if (hovered) {
        rounded_box(dc, RGB(26, 32, 43), r, 7);
    }
    text_at(dc, glyph, r.left + 16, r.top + 9, active ? C_CYAN : C_MUTED, f_ui);
    text_at(dc, title, r.left + 48, r.top + 10, active ? C_TEXT : C_MUTED, f_ui);
}

static void draw_sidebar(HDC dc, int height, POINT mouse) {
    RECT side = make_rect(0, 0, 248, height);
    rect_fill(dc, C_SIDEBAR, side);
    text_at(dc, "P", 25, 22, C_CYAN, f_brand);
    text_at(dc, "POWERFULL", 57, 23, C_TEXT, f_brand);
    text_at(dc, "IDA  /  REVERSAL WORKBENCH", 58, 51, C_MUTED, f_small);
    divider(dc, 24, 78, 224, 78);
    text_at(dc, "WORKSPACE", 25, 98, C_MUTED, f_small);

    draw_nav_item(dc, make_rect(14, 118, 224, 156), "<>", "Disassembly", NAV_DISASM, hover_target == NAV_DISASM);
    draw_nav_item(dc, make_rect(14, 160, 224, 198), "o", "Control Flow", NAV_GRAPH, hover_target == NAV_GRAPH);
    draw_nav_item(dc, make_rect(14, 202, 224, 240), "#", "Strings", NAV_STRINGS, hover_target == NAV_STRINGS);
    draw_nav_item(dc, make_rect(14, 244, 224, 282), "<> ", "Imports", NAV_IMPORTS, hover_target == NAV_IMPORTS);

    text_at(dc, "EXTENSIONS", 25, 315, C_MUTED, f_small);
    RECT plugin = make_rect(24, 338, 224, 388);
    rounded_box(dc, hover_target == 20 ? RGB(35, 35, 58) : RGB(29, 35, 47), plugin, 7);
    text_at(dc, "+", 38, 346, C_PURPLE, f_ui);
    text_at(dc, "Plugin manager", 61, 346, C_TEXT, f_ui);
    text_at(dc, "3 active plugins", 61, 366, C_MUTED, f_small);

    text_at(dc, "SYSTEM", 25, height - 104, C_MUTED, f_small);
    text_at(dc, "v0.1.0  /  LOCAL BUILD", 25, height - 79, C_MUTED, f_small);
    text_at(dc, "o  Engine online", 25, height - 53, C_CYAN, f_small);
    (void)mouse;
}

static void draw_code_view(HDC dc, RECT area) {
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
    int y = area.top + 18;
    int comment_x = area.left + 405;
    int i;
    for (i = 0; i < 10; i++) {
        COLORREF row_color = i == 8 ? C_CYAN : C_MUTED;
        if (i == 8) rect_fill(dc, RGB(25, 47, 49), make_rect(area.left, y - 4, area.right, y + 20));
        text_at(dc, rows[i][0], area.left + 15, y, C_MUTED, f_code);
        text_at(dc, rows[i][1], area.left + 113, y, C_PURPLE, f_code);
        text_at(dc, rows[i][2], area.left + 193, y, C_TEXT, f_code);
        text_clipped(dc, rows[i][3], make_rect(comment_x, y, area.right - 10, y + 20), row_color, f_code);
        y += 27;
    }
}

static void draw_ai_panel(HDC dc, RECT area, POINT mouse) {
    rect_fill(dc, C_PANEL, area);
    divider(dc, area.left, area.top, area.left, area.bottom);
    text_at(dc, "AI COPILOT", area.left + 24, area.top + 27, C_TEXT, f_heading);
    text_at(dc, "FUNCTION INTELLIGENCE", area.left + 24, area.top + 56, C_MUTED, f_small);
    RECT online = make_rect(area.left + 24, area.top + 83, area.right - 24, area.top + 115);
    rounded_box(dc, RGB(45, 36, 75), online, 6);
    text_at(dc, "o  ONLINE / LOCAL MODE", online.left + 13, online.top + 9, C_PURPLE, f_small);

    RECT prompt = make_rect(area.left + 24, area.top + 137, area.right - 24, area.top + 181);
    rounded_box(dc, RGB(27, 33, 45), prompt, 6);
    text_clipped(dc, "Ask about this function...", make_rect(prompt.left + 12, prompt.top, prompt.right - 12, prompt.bottom), C_MUTED, f_small);
    text_at(dc, ">", prompt.right - 24, prompt.top + 13, C_CYAN, f_small);

    text_at(dc, "SUGGESTIONS", area.left + 24, area.top + 213, C_MUTED, f_small);
    text_at(dc, "Explain selected function", area.left + 24, area.top + 244, C_TEXT, f_small);
    text_at(dc, "Find dangerous calls", area.left + 24, area.top + 276, C_TEXT, f_small);
    text_at(dc, "Rename local variables", area.left + 24, area.top + 308, C_TEXT, f_small);
    divider(dc, area.left + 24, area.top + 335, area.right - 24, area.top + 335);
    text_at(dc, "PLUGINS", area.left + 24, area.top + 358, C_MUTED, f_small);
    text_at(dc, "o  AI Decompiler", area.left + 24, area.top + 390, C_CYAN, f_small);
    text_at(dc, "o  Pattern Hunter", area.left + 24, area.top + 418, C_CYAN, f_small);
    text_at(dc, "o  Hex Exporter", area.left + 24, area.top + 446, C_CYAN, f_small);
    (void)mouse;
}

static void draw_main(HDC dc, int width, int height, POINT mouse) {
    rect_fill(dc, C_BG, make_rect(0, 0, width, height));
    draw_sidebar(dc, height, mouse);
    divider(dc, 248, 0, 248, height);

    int ai_width = ai_open && width >= 1050 ? 302 : 0;
    int main_left = 249;
    int main_right = width - ai_width;
    int content_left = main_left + 28;
    int content_right = main_right - 28;
    if (content_right < content_left + 220) content_right = content_left + 220;

    rect_fill(dc, C_PANEL, make_rect(main_left, 0, main_right, 65));
    divider(dc, main_left, 64, main_right, 64);
    text_at(dc, "PROJECT /", content_left, 22, C_MUTED, f_small);
    text_clipped(dc, loaded_file, make_rect(content_left + 74, 17, main_right - 245, 43), C_TEXT, f_ui);

    RECT ai_button = make_rect(main_right - 214, 15, main_right - 128, 48);
    RECT open_button = make_rect(main_right - 116, 15, main_right - 24, 48);
    draw_button(dc, ai_button, ai_open ? "HIDE AI" : "SHOW AI", FALSE, hover_target == 30);
    draw_button(dc, open_button, "OPEN BINARY", TRUE, hover_target == 31);

    text_at(dc, active_nav == NAV_DISASM ? "DISASSEMBLY" : active_nav == NAV_GRAPH ? "CONTROL FLOW" : active_nav == NAV_STRINGS ? "STRINGS" : "IMPORTS", content_left, 91, C_TEXT, f_heading);
    text_at(dc, binary_loaded ? "x64  |  analysis indexed  |  read-only mode" : "x64  |  waiting for a binary", content_left, 120, C_MUTED, f_small);
    RECT analyze = make_rect(content_right - 106, 83, content_right, 119);
    draw_button(dc, analyze, "ANALYZE", FALSE, hover_target == 32);
    divider(dc, content_left, 143, content_right, 143);

    RECT code = make_rect(content_left, 157, content_right, height - 181);
    rect_fill(dc, RGB(15, 19, 27), code);
    draw_code_view(dc, code);
    divider(dc, content_left, height - 166, content_right, height - 166);
    text_at(dc, "FUNCTIONS", content_left + 15, height - 149, C_MUTED, f_small);
    text_at(dc, "sub_401000", content_left + 15, height - 121, C_CYAN, f_code);
    text_at(dc, "sub_401250", content_left + 168, height - 121, C_TEXT, f_code);
    text_at(dc, "ai::load_model", content_left + 321, height - 121, C_PURPLE, f_code);

    RECT console = make_rect(main_left, height - 92, main_right, height);
    rect_fill(dc, RGB(14, 18, 25), console);
    divider(dc, main_left, console.top, main_right, console.top);
    text_at(dc, "CONSOLE", content_left, console.top + 13, C_MUTED, f_small);
    text_at(dc, ">  engine: binary input pipeline ready", content_left, console.top + 37, C_CYAN, f_code);
    text_at(dc, status_text, content_left, console.top + 61, C_TEXT, f_code);
    if (ai_open && width >= 1050) draw_ai_panel(dc, make_rect(main_right, 65, width, height), mouse);
}

static void open_binary(HWND hwnd) {
    OPENFILENAMEA dialog;
    char file[MAX_PATH] = {0};
    memset(&dialog, 0, sizeof(dialog));
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = hwnd;
    dialog.lpstrFile = file;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrFilter = "Binary files\0*.exe;*.dll;*.sys;*.bin;*.elf\0All files\0*.*\0";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameA(&dialog)) {
        const char *slash = strrchr(file, '\\');
        copy_text(loaded_file, sizeof(loaded_file), slash ? slash + 1 : file);
        binary_loaded = TRUE;
        copy_text(status_text, sizeof(status_text), "Loaded binary. Analysis queued.");
        InvalidateRect(hwnd, NULL, FALSE);
    }
}

static int hit_target(int x, int y, int width, BOOL current_ai) {
    int main_right = width - (current_ai && width >= 1050 ? 302 : 0);
    if (x >= 14 && x < 224) {
        if (y >= 118 && y < 156) return NAV_DISASM;
        if (y >= 160 && y < 198) return NAV_GRAPH;
        if (y >= 202 && y < 240) return NAV_STRINGS;
        if (y >= 244 && y < 282) return NAV_IMPORTS;
    }
    if (x >= main_right - 214 && x < main_right - 128 && y >= 15 && y < 48) return 30;
    if (x >= main_right - 116 && x < main_right - 24 && y >= 15 && y < 48) return 31;
    if (x >= 277 && x < main_right - 28 && y >= 83 && y < 119) return 32;
    return 0;
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    switch (message) {
    case WM_CREATE:
        SetTimer(hwnd, 1, 250, NULL);
        return 0;
    case WM_TIMER:
        KillTimer(hwnd, 1);
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_MOUSEMOVE: {
        RECT client; POINT mouse = {LOWORD(lp), HIWORD(lp)};
        GetClientRect(hwnd, &client);
        int target = hit_target(mouse.x, mouse.y, client.right, ai_open);
        if (target != hover_target) {
            hover_target = target;
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    }
    case WM_LBUTTONDOWN: {
        RECT client; POINT mouse = {LOWORD(lp), HIWORD(lp)};
        GetClientRect(hwnd, &client);
        int target = hit_target(mouse.x, mouse.y, client.right, ai_open);
        if (target >= NAV_DISASM && target <= NAV_IMPORTS) {
            active_nav = target;
            copy_text(status_text, sizeof(status_text), "View changed. Analysis context preserved.");
        } else if (target == 30) {
            ai_open = !ai_open;
            copy_text(status_text, sizeof(status_text), ai_open ? "AI copilot panel opened." : "AI copilot panel hidden.");
        } else if (target == 31) {
            open_binary(hwnd);
        } else if (target == 32) {
            copy_text(status_text, sizeof(status_text), binary_loaded ? "Analysis complete. 3 functions identified." : "Open a binary before starting analysis.");
        }
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    case WM_KEYDOWN:
        if (wp == VK_F1) {
            ai_open = !ai_open;
            InvalidateRect(hwnd, NULL, FALSE);
        }
        if (wp == VK_F5) {
            copy_text(status_text, sizeof(status_text), binary_loaded ? "Analysis complete. 3 functions identified." : "Open a binary before starting analysis.");
            InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    case WM_SIZE:
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT paint;
        RECT client;
        POINT mouse;
        HDC dc = BeginPaint(hwnd, &paint);
        HDC buffer;
        HBITMAP bitmap;
        HBITMAP old_bitmap;
        GetClientRect(hwnd, &client);
        GetCursorPos(&mouse);
        ScreenToClient(hwnd, &mouse);
        buffer = CreateCompatibleDC(dc);
        bitmap = CreateCompatibleBitmap(dc, client.right, client.bottom);
        old_bitmap = (HBITMAP)SelectObject(buffer, bitmap);
        draw_main(buffer, client.right, client.bottom, mouse);
        BitBlt(dc, 0, 0, client.right, client.bottom, buffer, 0, 0, SRCCOPY);
        SelectObject(buffer, old_bitmap);
        DeleteObject(bitmap);
        DeleteDC(buffer);
        EndPaint(hwnd, &paint);
        return 0;
    }
    case WM_DESTROY:
        KillTimer(hwnd, 1);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, message, wp, lp);
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE unused, LPSTR command, int show) {
    WNDCLASSA window_class;
    HWND window;
    MSG message;
    (void)unused;
    (void)command;
    SetProcessDPIAware();

    f_ui = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
    f_small = CreateFontA(11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
    f_heading = CreateFontA(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
    f_brand = CreateFontA(19, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
    f_code = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, DEFAULT_QUALITY, FIXED_PITCH, "Consolas");

    memset(&window_class, 0, sizeof(window_class));
    window_class.hInstance = instance;
    window_class.lpfnWndProc = window_proc;
    window_class.lpszClassName = "PowerfullIDA";
    window_class.hCursor = LoadCursor(NULL, IDC_ARROW);
    window_class.hbrBackground = CreateSolidBrush(C_BG);
    RegisterClassA(&window_class);
    window = CreateWindowExA(0, window_class.lpszClassName, "Powerfull IDA - Reversal Workbench", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 1400, 860, NULL, NULL, instance, NULL);
    if (!window) return 1;
    ShowWindow(window, show);
    UpdateWindow(window);
    while (GetMessageA(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageA(&message);
    }
    DeleteObject(f_ui);
    DeleteObject(f_small);
    DeleteObject(f_heading);
    DeleteObject(f_brand);
    DeleteObject(f_code);
    return (int)message.wParam;
}
