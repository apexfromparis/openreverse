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

    ImFont* robotoFont = io.Fonts->AddFontFromMemoryTTF((void*)font_roboto_medium, (int)sizeof(font_roboto_medium), 13.0f, &config);
    if (robotoFont) {
        io.FontDefault = robotoFont;
    }

    char winDir[MAX_PATH];
    const bool hasWinDir = (GetWindowsDirectoryA(winDir, MAX_PATH) != 0);
    std::string fontsPath = hasWinDir ? (std::string(winDir) + "\\Fonts\\") : "";

    if (!fontsPath.empty())
    {
        config.FontDataOwnedByAtlas = true;
        ImFont* mono = io.Fonts->AddFontFromFileTTF((fontsPath + "consola.ttf").c_str(), 12.0f, &config);
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

void UIManager::PanelHeader(const char* title, const char* context)
{
    const ImVec2 start = ImGui::GetCursorScreenPos();
    const float height = 26.0f;
    const float width = ImGui::GetContentRegionAvail().x;
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(start, ImVec2(start.x + width, start.y + height),
        IM_COL32(8, 16, 22, 255));
    draw->AddLine(ImVec2(start.x, start.y + height - 1.0f),
        ImVec2(start.x + width, start.y + height - 1.0f), IM_COL32(27, 48, 61, 255));
    draw->AddText(ImVec2(start.x + 8.0f, start.y + 5.0f), IM_COL32(231, 237, 242, 255), title);

    if (context && context[0] != '\0')
    {
        const float contextWidth = ImGui::CalcTextSize(context).x;
        draw->AddText(ImVec2(start.x + width - contextWidth - 8.0f, start.y + 5.0f),
            IM_COL32(121, 137, 149, 255), context);
    }
    ImGui::Dummy(ImVec2(width, height));
}

void UIManager::SectionLabel(const char* label, const char* value)
{
    ImGui::Spacing();
    ImGui::TextColored(ImVec4(0.78f, 0.82f, 0.86f, 1.0f), "%s", label);
    if (value && value[0] != '\0')
    {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", value);
    }
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::GetWindowDrawList()->AddLine(p, ImVec2(p.x + ImGui::GetContentRegionAvail().x, p.y),
        IM_COL32(28, 43, 53, 255));
    ImGui::Dummy(ImVec2(0.0f, 3.0f));
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

    style.WindowRounding    = 3.0f;
    style.ChildRounding     = 2.0f;
    style.FrameRounding     = 2.0f;
    style.PopupRounding     = 3.0f;
    style.GrabRounding      = 2.0f;
    style.TabRounding       = 2.0f;
    style.ScrollbarRounding = 2.0f;
    style.WindowBorderSize  = 1.0f;
    style.ChildBorderSize   = 1.0f;
    style.FrameBorderSize   = 1.0f;
    style.PopupBorderSize   = 1.0f;
    style.WindowPadding     = ImVec2(8.0f, 6.0f);
    style.FramePadding      = ImVec2(5.0f, 3.0f);
    style.ItemSpacing       = ImVec2(6.0f, 4.0f);
    style.ItemInnerSpacing  = ImVec2(4.0f, 3.0f);
    style.IndentSpacing     = 15.0f;
    style.ScrollbarSize     = 9.0f;
    style.GrabMinSize       = 6.0f;
    style.TabBorderSize     = 0.0f;

    ImVec4 bgMain       = ImVec4(5.0f/255.0f, 9.0f/255.0f, 13.0f/255.0f, 1.00f);
    ImVec4 bgBox        = ImVec4(8.0f/255.0f, 14.0f/255.0f, 19.0f/255.0f, 1.00f);
    ImVec4 bgWidget     = ImVec4(12.0f/255.0f, 21.0f/255.0f, 28.0f/255.0f, 1.00f);
    ImVec4 borderCol    = ImVec4(25.0f/255.0f, 43.0f/255.0f, 55.0f/255.0f, 1.00f);
    ImVec4 borderWidget = ImVec4(35.0f/255.0f, 64.0f/255.0f, 82.0f/255.0f, 1.00f);

    ImVec4 textMain     = ImVec4(255.0f/255.0f, 255.0f/255.0f, 255.0f/255.0f, 1.00f);
    ImVec4 textDim      = ImVec4(110.0f/255.0f, 110.0f/255.0f, 110.0f/255.0f, 1.00f);
    ImVec4 textDisabled = ImVec4(80.0f/255.0f,  80.0f/255.0f,  80.0f/255.0f,  1.00f);

    ImVec4 accentDim    = ImVec4(0.00f, 0.24f, 0.48f, 1.00f);
    ImVec4 accent       = ImVec4(0.00f, 0.46f, 0.92f, 1.00f);
    ImVec4 accentBright = ImVec4(0.10f, 0.64f, 1.00f, 1.00f);
    ImVec4 green        = ImVec4(0.000f, 0.902f, 0.463f, 1.00f);

    colors[ImGuiCol_Text]                  = textMain;
    colors[ImGuiCol_TextDisabled]          = textDisabled;
    colors[ImGuiCol_WindowBg]              = bgMain;
    colors[ImGuiCol_ChildBg]               = bgBox;
    colors[ImGuiCol_PopupBg]               = ImVec4(7.0f/255.0f, 13.0f/255.0f, 18.0f/255.0f, 0.98f);
    colors[ImGuiCol_Border]                = borderCol;
    colors[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]               = bgWidget;
    colors[ImGuiCol_FrameBgHovered]        = ImVec4(0.03f, 0.17f, 0.27f, 1.00f);
    colors[ImGuiCol_FrameBgActive]         = ImVec4(0.02f, 0.25f, 0.43f, 1.00f);
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
    colors[ImGuiCol_ButtonHovered]         = ImVec4(0.02f, 0.24f, 0.42f, 1.00f);
    colors[ImGuiCol_ButtonActive]          = accentDim;
    colors[ImGuiCol_Header]                = ImVec4(0.00f, 0.18f, 0.38f, 1.00f);
    colors[ImGuiCol_HeaderHovered]         = ImVec4(0.00f, 0.28f, 0.58f, 1.00f);
    colors[ImGuiCol_HeaderActive]          = ImVec4(0.00f, 0.34f, 0.72f, 1.00f);
    colors[ImGuiCol_Separator]             = borderCol;
    colors[ImGuiCol_SeparatorHovered]      = borderWidget;
    colors[ImGuiCol_SeparatorActive]       = accent;
    colors[ImGuiCol_ResizeGrip]            = ImVec4(35.0f/255.0f, 35.0f/255.0f, 35.0f/255.0f, 0.40f);
    colors[ImGuiCol_ResizeGripHovered]     = borderWidget;
    colors[ImGuiCol_ResizeGripActive]      = accent;
    colors[ImGuiCol_Tab]                   = bgBox;
    colors[ImGuiCol_TabHovered]            = ImVec4(0.02f, 0.24f, 0.42f, 1.00f);
    colors[ImGuiCol_TabSelected]           = ImVec4(0.01f, 0.18f, 0.32f, 1.00f);
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
    colors[ImGuiCol_TextSelectedBg]        = ImVec4(0.00f, 0.35f, 0.75f, 0.55f);
    colors[ImGuiCol_DragDropTarget]        = textMain;
    colors[ImGuiCol_NavHighlight]          = accent;
    colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.00f, 1.00f, 1.00f, 0.12f);
    colors[ImGuiCol_NavWindowingDimBg]     = ImVec4(0.00f, 0.00f, 0.00f, 0.50f);
    colors[ImGuiCol_ModalWindowDimBg]      = ImVec4(0.00f, 0.00f, 0.00f, 0.50f);
}

} // namespace openreverse
