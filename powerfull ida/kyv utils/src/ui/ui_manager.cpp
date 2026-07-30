// ============================================================================
// KYV - UI Manager Implementation
// Professional dark theme + typography
// ============================================================================

#include "ui_manager.h"
#include <imgui.h>
#include <imgui_internal.h>
#include <windows.h>
#include <string>

namespace kyv {

static ImFont* s_monoFont = nullptr;

static void LoadFonts()
{
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();

    ImFontConfig config;
    config.OversampleH = 2;
    config.OversampleV = 2;
    config.PixelSnapH = true;

    char winDir[MAX_PATH];
    const bool hasWinDir = (GetWindowsDirectoryA(winDir, MAX_PATH) != 0);
    std::string fontsPath = hasWinDir ? (std::string(winDir) + "\\Fonts\\") : "";

    if (!fontsPath.empty())
    {
        ImFont* uiFont = io.Fonts->AddFontFromFileTTF((fontsPath + "segoeui.ttf").c_str(), 14.0f, &config);
        if (uiFont)
            io.FontDefault = uiFont;
        config.MergeMode = false;
        ImFont* mono = io.Fonts->AddFontFromFileTTF((fontsPath + "consola.ttf").c_str(), 13.0f, &config);
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
    style.WindowRounding    = 4.0f;
    style.ChildRounding     = 4.0f;
    style.FrameRounding     = 4.0f;
    style.GrabRounding      = 3.0f;
    style.TabRounding       = 4.0f;
    style.ScrollbarRounding = 4.0f;
    style.WindowBorderSize  = 1.0f;
    style.ChildBorderSize   = 1.0f;
    style.FrameBorderSize   = 0.0f;
    style.PopupBorderSize   = 1.0f;
    style.WindowPadding     = ImVec2(12.0f, 9.0f);
    style.FramePadding      = ImVec2(8.0f, 5.0f);
    style.ItemSpacing       = ImVec2(8.0f, 6.0f);
    style.ItemInnerSpacing  = ImVec2(6.0f, 4.0f);
    style.IndentSpacing     = 18.0f;
    style.ScrollbarSize     = 12.0f;
    style.GrabMinSize       = 8.0f;
    style.TabBorderSize     = 0.0f;

    // ─── Cyber-obscidian palette: cyan for navigation, purple for AI ──────────
    ImVec4 bgDark    = ImVec4(0.039f, 0.047f, 0.063f, 1.00f);
    ImVec4 bgMedium  = ImVec4(0.078f, 0.094f, 0.133f, 1.00f);
    ImVec4 bgLight   = ImVec4(0.110f, 0.137f, 0.192f, 1.00f);

    ImVec4 accentDim    = ImVec4(0.000f, 0.420f, 0.510f, 1.00f);
    ImVec4 accent       = ImVec4(0.000f, 0.650f, 0.740f, 1.00f);
    ImVec4 accentBright = ImVec4(0.000f, 0.898f, 1.000f, 1.00f);
    ImVec4 green        = ImVec4(0.000f, 0.902f, 0.463f, 1.00f);
    ImVec4 warning      = ImVec4(1.000f, 0.671f, 0.251f, 1.00f);

    ImVec4 textMain     = ImVec4(0.922f, 0.941f, 0.980f, 1.00f);
    ImVec4 textDim      = ImVec4(0.522f, 0.580f, 0.663f, 1.00f);
    ImVec4 textDisabled = ImVec4(0.294f, 0.341f, 0.420f, 1.00f);

    ImVec4 border = ImVec4(0.169f, 0.204f, 0.267f, 1.00f);

    // Apply colors
    colors[ImGuiCol_Text]                  = textMain;
    colors[ImGuiCol_TextDisabled]          = textDisabled;
    colors[ImGuiCol_WindowBg]              = bgMedium;
    colors[ImGuiCol_ChildBg]               = bgDark;
    colors[ImGuiCol_PopupBg]               = ImVec4(0.08f, 0.08f, 0.11f, 0.96f);
    colors[ImGuiCol_Border]                = border;
    colors[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]               = ImVec4(0.110f, 0.137f, 0.192f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]        = ImVec4(0.161f, 0.212f, 0.278f, 1.00f);
    colors[ImGuiCol_FrameBgActive]         = ImVec4(0.000f, 0.260f, 0.310f, 1.00f);
    colors[ImGuiCol_TitleBg]               = bgDark;
    colors[ImGuiCol_TitleBgActive]         = ImVec4(0.08f, 0.08f, 0.12f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]      = ImVec4(0.04f, 0.04f, 0.06f, 0.80f);
    colors[ImGuiCol_MenuBarBg]             = bgDark;
    colors[ImGuiCol_ScrollbarBg]           = ImVec4(0.04f, 0.04f, 0.06f, 0.60f);
    colors[ImGuiCol_ScrollbarGrab]         = ImVec4(0.169f, 0.204f, 0.267f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered]  = accentDim;
    colors[ImGuiCol_ScrollbarGrabActive]   = accent;
    colors[ImGuiCol_CheckMark]             = green;
    colors[ImGuiCol_SliderGrab]            = accent;
    colors[ImGuiCol_SliderGrabActive]      = accentBright;
    colors[ImGuiCol_Button]                = ImVec4(0.122f, 0.149f, 0.200f, 1.00f);
    colors[ImGuiCol_ButtonHovered]         = accentDim;
    colors[ImGuiCol_ButtonActive]          = accent;
    colors[ImGuiCol_Header]                = ImVec4(0.122f, 0.149f, 0.200f, 1.00f);
    colors[ImGuiCol_HeaderHovered]         = accentDim;
    colors[ImGuiCol_HeaderActive]          = accent;
    colors[ImGuiCol_Separator]             = border;
    colors[ImGuiCol_SeparatorHovered]      = accent;
    colors[ImGuiCol_SeparatorActive]       = accentBright;
    colors[ImGuiCol_ResizeGrip]            = ImVec4(0.14f, 0.14f, 0.20f, 0.40f);
    colors[ImGuiCol_ResizeGripHovered]     = accent;
    colors[ImGuiCol_ResizeGripActive]      = accentBright;
    colors[ImGuiCol_Tab]                   = bgLight;
    colors[ImGuiCol_TabHovered]            = accent;
    colors[ImGuiCol_TabSelected]           = accentDim;
    colors[ImGuiCol_TabDimmed]             = bgDark;
    colors[ImGuiCol_TabDimmedSelected]     = ImVec4(0.000f, 0.260f, 0.310f, 1.00f);
    colors[ImGuiCol_DockingPreview]        = ImVec4(0.15f, 0.55f, 0.75f, 0.70f);
    colors[ImGuiCol_DockingEmptyBg]        = bgDark;
    colors[ImGuiCol_PlotLines]             = accent;
    colors[ImGuiCol_PlotLinesHovered]      = accentBright;
    colors[ImGuiCol_PlotHistogram]         = accent;
    colors[ImGuiCol_PlotHistogramHovered]  = accentBright;
    colors[ImGuiCol_TableHeaderBg]         = bgLight;
    colors[ImGuiCol_TableBorderStrong]     = border;
    colors[ImGuiCol_TableBorderLight]      = ImVec4(0.12f, 0.12f, 0.17f, 1.00f);
    colors[ImGuiCol_TableRowBg]            = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]         = ImVec4(0.039f, 0.063f, 0.094f, 0.70f);
    colors[ImGuiCol_TextSelectedBg]        = ImVec4(0.000f, 0.650f, 0.740f, 0.30f);
    colors[ImGuiCol_DragDropTarget]        = warning;
    colors[ImGuiCol_NavHighlight]          = accent;
    colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.00f, 1.00f, 1.00f, 0.12f);
    colors[ImGuiCol_NavWindowingDimBg]     = ImVec4(0.00f, 0.00f, 0.00f, 0.60f);
    colors[ImGuiCol_ModalWindowDimBg]      = ImVec4(0.00f, 0.00f, 0.00f, 0.60f);
}

} // namespace kyv
