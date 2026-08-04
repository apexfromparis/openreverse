// ============================================================================
// OpenReverse - UI Manager Implementation
// Professional dark theme + typography
// ============================================================================

#include "ui_manager.h"
#include "embedded_font.h"
#include <imgui.h>
#include <imgui_internal.h>
#include <windows.h>
#include <string>

namespace openreverse {

static ImFont* s_monoFont = nullptr;

static void LoadFonts()
{
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();

    ImFontConfig config;
    config.OversampleH = 3;
    config.OversampleV = 1;
    config.FontDataOwnedByAtlas = false;
    config.PixelSnapH = true;

    // Load Paris-main default Roboto-Medium font
    ImFont* robotoFont = io.Fonts->AddFontFromMemoryTTF((void*)font_roboto_medium, (int)sizeof(font_roboto_medium), 16.0f, &config);
    if (robotoFont) {
        io.FontDefault = robotoFont;
    }

    char winDir[MAX_PATH];
    const bool hasWinDir = (GetWindowsDirectoryA(winDir, MAX_PATH) != 0);
    std::string fontsPath = hasWinDir ? (std::string(winDir) + "\\Fonts\\") : "";

    if (!fontsPath.empty())
    {
        config.FontDataOwnedByAtlas = true;
        ImFont* mono = io.Fonts->AddFontFromFileTTF((fontsPath + "consola.ttf").c_str(), 14.0f, &config);
        if (mono)
            s_monoFont = mono;
    }
    if (!io.FontDefault)
        io.FontDefault = io.Fonts->AddFontDefault();
}

ImFont* UIManager::GetMonoFont()
{
    return s_monoFont;
}

bool UIManager::EmptyState(const char* message)
{
    ImGui::Spacing();
    ImGui::Indent(20.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.52f, 0.52f, 0.58f, 1.0f));
    ImGui::TextWrapped("%s", message);
    ImGui::PopStyleColor();
    ImGui::Unindent(20.0f);
    ImGui::Spacing();
    return true;
}

void UIManager::ToolbarSeparator()
{
    ImGui::SameLine();
    ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
    ImGui::SameLine();
}

void UIManager::BeginToolbar()
{
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f, 4.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.0f, 3.0f));
}

void UIManager::EndToolbar()
{
    ImGui::PopStyleVar(2);
}

void UIManager::ApplyTheme()
{
    LoadFonts();

    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    // ─── Layout: dense forensic workstation with restrained neon accents ─────
    style.WindowRounding    = 8.0f;
    style.ChildRounding     = 6.0f;
    style.FrameRounding     = 6.0f;
    style.PopupRounding     = 8.0f;
    style.GrabRounding      = 4.0f;
    style.TabRounding       = 4.0f;
    style.ScrollbarRounding = 4.0f;
    style.WindowBorderSize  = 1.0f;
    style.ChildBorderSize   = 1.0f;
    style.FrameBorderSize   = 1.0f;
    style.PopupBorderSize   = 1.0f;
    style.WindowPadding     = ImVec2(14.0f, 12.0f);
    style.FramePadding      = ImVec2(8.0f, 5.0f);
    style.ItemSpacing       = ImVec2(8.0f, 6.0f);
    style.ItemInnerSpacing  = ImVec2(6.0f, 4.0f);
    style.IndentSpacing     = 18.0f;
    style.ScrollbarSize     = 12.0f;
    style.GrabMinSize       = 8.0f;
    style.TabBorderSize     = 0.0f;

    // ─── Paris-main Cyber Dark Theme Palette (exact RGB tokens from menu.cpp) ───
    // C_BG = 15,15,15 | C_BOX_BG = 22,22,22 | C_BOX_BD = 35,35,35 | C_WIDGET_BG = 30,30,30
    ImVec4 bgMain       = ImVec4(15.0f/255.0f, 15.0f/255.0f, 15.0f/255.0f, 1.00f);
    ImVec4 bgBox        = ImVec4(22.0f/255.0f, 22.0f/255.0f, 22.0f/255.0f, 1.00f);
    ImVec4 bgWidget     = ImVec4(30.0f/255.0f, 30.0f/255.0f, 30.0f/255.0f, 1.00f);
    ImVec4 borderCol    = ImVec4(35.0f/255.0f, 35.0f/255.0f, 35.0f/255.0f, 1.00f);
    ImVec4 borderWidget = ImVec4(50.0f/255.0f, 50.0f/255.0f, 50.0f/255.0f, 1.00f);

    ImVec4 textMain     = ImVec4(255.0f/255.0f, 255.0f/255.0f, 255.0f/255.0f, 1.00f); // Pure white C_TEXT_ACT
    ImVec4 textDim      = ImVec4(110.0f/255.0f, 110.0f/255.0f, 110.0f/255.0f, 1.00f); // C_TEXT_DIM
    ImVec4 textDisabled = ImVec4(80.0f/255.0f,  80.0f/255.0f,  80.0f/255.0f,  1.00f);

    ImVec4 accentDim    = ImVec4(45.0f/255.0f,  45.0f/255.0f,  45.0f/255.0f,  1.00f);
    ImVec4 accent       = ImVec4(65.0f/255.0f,  65.0f/255.0f,  65.0f/255.0f,  1.00f);
    ImVec4 accentBright = ImVec4(180.0f/255.0f, 180.0f/255.0f, 180.0f/255.0f, 1.00f);
    ImVec4 green        = ImVec4(0.000f, 0.902f, 0.463f, 1.00f);

    colors[ImGuiCol_Text]                  = textMain;
    colors[ImGuiCol_TextDisabled]          = textDisabled;
    colors[ImGuiCol_WindowBg]              = bgMain;
    colors[ImGuiCol_ChildBg]               = bgBox;
    colors[ImGuiCol_PopupBg]               = ImVec4(20.0f/255.0f, 20.0f/255.0f, 20.0f/255.0f, 0.96f);
    colors[ImGuiCol_Border]                = borderCol;
    colors[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]               = bgWidget;
    colors[ImGuiCol_FrameBgHovered]        = ImVec4(42.0f/255.0f, 42.0f/255.0f, 42.0f/255.0f, 1.00f);
    colors[ImGuiCol_FrameBgActive]         = ImVec4(55.0f/255.0f, 55.0f/255.0f, 55.0f/255.0f, 1.00f);
    colors[ImGuiCol_TitleBg]               = bgMain;
    colors[ImGuiCol_TitleBgActive]         = bgBox;
    colors[ImGuiCol_TitleBgCollapsed]      = bgMain;
    colors[ImGuiCol_MenuBarBg]             = bgMain;
    colors[ImGuiCol_ScrollbarBg]           = ImVec4(15.0f/255.0f, 15.0f/255.0f, 15.0f/255.0f, 0.60f);
    colors[ImGuiCol_ScrollbarGrab]         = borderWidget;
    colors[ImGuiCol_ScrollbarGrabHovered]  = accentDim;
    colors[ImGuiCol_ScrollbarGrabActive]   = accent;
    colors[ImGuiCol_CheckMark]             = textMain;
    colors[ImGuiCol_SliderGrab]            = textMain;
    colors[ImGuiCol_SliderGrabActive]      = accentBright;
    colors[ImGuiCol_Button]                = bgWidget;
    colors[ImGuiCol_ButtonHovered]         = ImVec4(42.0f/255.0f, 42.0f/255.0f, 42.0f/255.0f, 1.00f);
    colors[ImGuiCol_ButtonActive]          = ImVec4(55.0f/255.0f, 55.0f/255.0f, 55.0f/255.0f, 1.00f);
    colors[ImGuiCol_Header]                = bgWidget;
    colors[ImGuiCol_HeaderHovered]         = ImVec4(42.0f/255.0f, 42.0f/255.0f, 42.0f/255.0f, 1.00f);
    colors[ImGuiCol_HeaderActive]          = ImVec4(55.0f/255.0f, 55.0f/255.0f, 55.0f/255.0f, 1.00f);
    colors[ImGuiCol_Separator]             = borderCol;
    colors[ImGuiCol_SeparatorHovered]      = borderWidget;
    colors[ImGuiCol_SeparatorActive]       = accent;
    colors[ImGuiCol_ResizeGrip]            = ImVec4(35.0f/255.0f, 35.0f/255.0f, 35.0f/255.0f, 0.40f);
    colors[ImGuiCol_ResizeGripHovered]     = borderWidget;
    colors[ImGuiCol_ResizeGripActive]      = accent;
    colors[ImGuiCol_Tab]                   = bgBox;
    colors[ImGuiCol_TabHovered]            = ImVec4(42.0f/255.0f, 42.0f/255.0f, 42.0f/255.0f, 1.00f);
    colors[ImGuiCol_TabSelected]           = bgWidget;
    colors[ImGuiCol_TabDimmed]             = bgMain;
    colors[ImGuiCol_DockingPreview]        = ImVec4(0.15f, 0.55f, 0.75f, 0.70f);
    colors[ImGuiCol_DockingEmptyBg]        = bgMain;
    colors[ImGuiCol_PlotLines]             = accent;
    colors[ImGuiCol_PlotLinesHovered]      = accentBright;
    colors[ImGuiCol_PlotHistogram]         = accent;
    colors[ImGuiCol_PlotHistogramHovered]  = accentBright;
    colors[ImGuiCol_TableHeaderBg]         = bgBox;
    colors[ImGuiCol_TableBorderStrong]     = borderCol;
    colors[ImGuiCol_TableBorderLight]      = borderWidget;
    colors[ImGuiCol_TableRowBg]            = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]         = ImVec4(20.0f/255.0f, 20.0f/255.0f, 20.0f/255.0f, 0.70f);
    colors[ImGuiCol_TextSelectedBg]        = ImVec4(65.0f/255.0f, 65.0f/255.0f, 65.0f/255.0f, 0.40f);
    colors[ImGuiCol_DragDropTarget]        = textMain;
    colors[ImGuiCol_NavHighlight]          = accent;
    colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.00f, 1.00f, 1.00f, 0.12f);
    colors[ImGuiCol_NavWindowingDimBg]     = ImVec4(0.00f, 0.00f, 0.00f, 0.50f);
    colors[ImGuiCol_ModalWindowDimBg]      = ImVec4(0.00f, 0.00f, 0.00f, 0.50f);
}

} // namespace openreverse
