#include "workspace_ui.h"
#include "embedded_font.h"
#include <imgui.h>
#include <imgui_internal.h>
#include <windows.h>
#include <filesystem>
#include <string>
#include <vector>

namespace openreverse {
namespace {

ImFont* monoFont = nullptr;
ImFont* defaultFont = nullptr;

static void LoadFonts()
{
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();

    ImFontConfig config;
    config.OversampleH = 3;
    config.OversampleV = 1;
    config.FontDataOwnedByAtlas = false;
    config.PixelSnapH = true;

    ImFont* robotoFont = io.Fonts->AddFontFromMemoryTTF((void*)font_roboto_medium, (int)sizeof(font_roboto_medium), 14.0f, &config);
    if (robotoFont) {
        io.FontDefault = robotoFont;
        defaultFont = robotoFont;
    }

    const UINT windowsLength = GetWindowsDirectoryW(nullptr, 0);
    std::vector<wchar_t> windowsDirectory(static_cast<size_t>(windowsLength) + 1, L'\0');
    if (windowsLength != 0 &&
        GetWindowsDirectoryW(windowsDirectory.data(), static_cast<UINT>(windowsDirectory.size())) != 0)
    {
        const std::filesystem::path monoPath = std::filesystem::path(windowsDirectory.data()) /
            L"Fonts" / L"consola.ttf";
        const std::string monoPathUtf8 = monoPath.u8string();
        config.FontDataOwnedByAtlas = true;
        ImFont* mono = io.Fonts->AddFontFromFileTTF(monoPathUtf8.c_str(), 13.0f, &config);
        if (mono)
            monoFont = mono;
    }
    if (!io.FontDefault)
    {
        io.FontDefault = io.Fonts->AddFontDefault();
        defaultFont = io.FontDefault;
    }
}

} // namespace

ImFont* workspace_ui::GetMonoFont()
{
    return monoFont;
}

ImFont* workspace_ui::GetDefaultFont()
{
    return defaultFont;
}

bool workspace_ui::EmptyState(const char* message)
{
    ImGui::Spacing();
    ImGui::Indent(20.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.58f, 0.65f, 1.0f));
    ImGui::TextWrapped("%s", message);
    ImGui::PopStyleColor();
    ImGui::Unindent(20.0f);
    ImGui::Spacing();
    return true;
}

void workspace_ui::PanelHeader(const char* title, const char* context)
{
    const ImVec2 start = ImGui::GetCursorScreenPos();
    const float height = 28.0f;
    const float width = ImGui::GetContentRegionAvail().x;
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(start, ImVec2(start.x + width, start.y + height),
        IM_COL32(19, 21, 27, 255));
    draw->AddLine(ImVec2(start.x, start.y + height - 1.0f),
        ImVec2(start.x + width, start.y + height - 1.0f), IM_COL32(38, 41, 52, 255));
    draw->AddText(ImVec2(start.x + 10.0f, start.y + 6.0f), IM_COL32(235, 238, 245, 255), title);

    if (context && context[0] != '\0')
    {
        const float contextWidth = ImGui::CalcTextSize(context).x;
        draw->AddText(ImVec2(start.x + width - contextWidth - 10.0f, start.y + 6.0f),
            IM_COL32(138, 145, 160, 255), context);
    }
    ImGui::Dummy(ImVec2(width, height));
}

void workspace_ui::SectionLabel(const char* label, const char* value)
{
    ImGui::Spacing();
    ImGui::TextColored(ImVec4(0.85f, 0.88f, 0.94f, 1.0f), "%s", label);
    if (value && value[0] != '\0')
    {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", value);
    }
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::GetWindowDrawList()->AddLine(p, ImVec2(p.x + ImGui::GetContentRegionAvail().x, p.y),
        IM_COL32(38, 42, 54, 255));
    ImGui::Dummy(ImVec2(0.0f, 4.0f));
}

void workspace_ui::ToolbarSeparator()
{
    ImGui::SameLine();
    ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
    ImGui::SameLine();
}

void workspace_ui::BeginToolbar()
{
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6.0f, 4.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.0f, 4.0f));
}

void workspace_ui::EndToolbar()
{
    ImGui::PopStyleVar(2);
}

void workspace_ui::CardBegin(const char* id, const ImVec2& size, bool interactive)
{
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.0f, 14.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(24.0f/255.0f, 27.0f/255.0f, 35.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(42.0f/255.0f, 46.0f/255.0f, 58.0f/255.0f, 1.0f));
    
    ImGuiWindowFlags flags = ImGuiWindowFlags_None;
    if (!interactive) flags |= ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    
    ImGui::BeginChild(id, size, true, flags);
}

void workspace_ui::CardEnd()
{
    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(3);
}

bool workspace_ui::NavItem(const char* id, const char* label, const char* iconText, bool active, float width)
{
    const float availWidth = width > 0.0f ? width : ImGui::GetContentRegionAvail().x;
    const float height = 36.0f;
    const ImVec2 p = ImGui::GetCursorScreenPos();
    
    const bool clicked = ImGui::InvisibleButton(id, ImVec2(availWidth, height));
    const bool hovered = ImGui::IsItemHovered();
    
    ImDrawList* draw = ImGui::GetWindowDrawList();
    
    ImU32 bgCol = 0;
    ImU32 textCol = IM_COL32(158, 163, 176, 255);
    
    if (active)
    {
        bgCol = IM_COL32(40, 48, 70, 255);
        textCol = IM_COL32(245, 247, 252, 255);
        // Active indicator line on the left
        draw->AddRectFilled(ImVec2(p.x + 2.0f, p.y + 7.0f), ImVec2(p.x + 5.0f, p.y + height - 7.0f),
            IM_COL32(78, 117, 255, 255), 2.0f);
    }
    else if (hovered)
    {
        bgCol = IM_COL32(30, 34, 45, 255);
        textCol = IM_COL32(220, 224, 235, 255);
    }
    
    if (bgCol != 0)
    {
        draw->AddRectFilled(ImVec2(p.x, p.y), ImVec2(p.x + availWidth, p.y + height), bgCol, 6.0f);
    }
    
    // Draw icon text / glyph
    if (iconText && iconText[0] != '\0')
    {
        draw->AddText(ImVec2(p.x + 14.0f, p.y + 9.0f), active ? IM_COL32(78, 117, 255, 255) : textCol, iconText);
    }
    
    // Draw label
    const float textOffset = (iconText && iconText[0] != '\0') ? 36.0f : 14.0f;
    draw->AddText(ImVec2(p.x + textOffset, p.y + 9.0f), textCol, label);
    
    return clicked;
}

void workspace_ui::Badge(const char* text, ImU32 bgCol, ImU32 textCol)
{
    const ImVec2 textSize = ImGui::CalcTextSize(text);
    const float padX = 7.0f;
    const float padY = 2.0f;
    const float width = textSize.x + padX * 2.0f;
    const float height = textSize.y + padY * 2.0f;
    
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(p, ImVec2(p.x + width, p.y + height), bgCol, 4.0f);
    draw->AddText(ImVec2(p.x + padX, p.y + padY), textCol, text);
    ImGui::Dummy(ImVec2(width, height));
}

bool workspace_ui::PrimaryButton(const char* label, const ImVec2& size)
{
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.24f, 0.38f, 0.96f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.32f, 0.46f, 1.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.18f, 0.30f, 0.85f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 5.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14.0f, 7.0f));
    
    const bool clicked = ImGui::Button(label, size);
    
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(4);
    return clicked;
}

bool workspace_ui::SecondaryButton(const char* label, const ImVec2& size)
{
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.14f, 0.18f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.18f, 0.20f, 0.26f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.10f, 0.12f, 0.15f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.24f, 0.27f, 0.35f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.85f, 0.88f, 0.94f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 5.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14.0f, 7.0f));
    
    const bool clicked = ImGui::Button(label, size);
    
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(5);
    return clicked;
}

void workspace_ui::AvatarCircle(const ImVec2& center, float radius, const char* initials, ImU32 bgCol, ImU32 textCol)
{
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const ImU32 actualBg = bgCol != 0 ? bgCol : IM_COL32(60, 75, 120, 255);
    const ImU32 actualText = textCol != 0 ? textCol : IM_COL32(245, 247, 255, 255);
    
    draw->AddCircleFilled(center, radius, actualBg, 24);
    
    if (initials && initials[0] != '\0')
    {
        const ImVec2 textSize = ImGui::CalcTextSize(initials);
        draw->AddText(ImVec2(center.x - textSize.x * 0.5f, center.y - textSize.y * 0.5f), actualText, initials);
    }
}

void workspace_ui::TextMuted(const char* text)
{
    ImGui::TextColored(ImVec4(0.55f, 0.58f, 0.65f, 1.0f), "%s", text);
}

void workspace_ui::TextHeading(const char* text, int level)
{
    if (level == 1)
    {
        ImGui::TextColored(ImVec4(0.96f, 0.97f, 1.0f, 1.0f), "%s", text);
    }
    else
    {
        ImGui::TextColored(ImVec4(0.85f, 0.88f, 0.94f, 1.0f), "%s", text);
    }
}

void workspace_ui::ApplyTheme()
{
    LoadFonts();

    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    style.WindowRounding    = 6.0f;
    style.ChildRounding     = 5.0f;
    style.FrameRounding     = 5.0f;
    style.PopupRounding     = 6.0f;
    style.GrabRounding      = 3.0f;
    style.TabRounding       = 4.0f;
    style.ScrollbarRounding = 4.0f;
    style.WindowBorderSize  = 1.0f;
    style.ChildBorderSize   = 1.0f;
    style.FrameBorderSize   = 1.0f;
    style.PopupBorderSize   = 1.0f;
    style.WindowPadding     = ImVec2(10.0f, 8.0f);
    style.FramePadding      = ImVec2(7.0f, 4.0f);
    style.ItemSpacing       = ImVec2(8.0f, 5.0f);
    style.ItemInnerSpacing  = ImVec2(5.0f, 4.0f);
    style.IndentSpacing     = 16.0f;
    style.ScrollbarSize     = 10.0f;
    style.GrabMinSize       = 8.0f;
    style.TabBorderSize     = 0.0f;

    // Modern Product Dark Theme Palette (Slate / Linear / Raycast style)
    const ImVec4 bgBase        = ImVec4(14.0f/255.0f, 15.0f/255.0f, 19.0f/255.0f, 1.00f);
    const ImVec4 bgSurface     = ImVec4(20.0f/255.0f, 22.0f/255.0f, 28.0f/255.0f, 1.00f);
    const ImVec4 bgWidget      = ImVec4(27.0f/255.0f, 30.0f/255.0f, 38.0f/255.0f, 1.00f);
    const ImVec4 bgHover       = ImVec4(35.0f/255.0f, 39.0f/255.0f, 50.0f/255.0f, 1.00f);
    const ImVec4 bgActive      = ImVec4(45.0f/255.0f, 50.0f/255.0f, 65.0f/255.0f, 1.00f);
    
    const ImVec4 borderSubtle  = ImVec4(38.0f/255.0f, 42.0f/255.0f, 53.0f/255.0f, 1.00f);
    const ImVec4 borderStrong  = ImVec4(52.0f/255.0f, 58.0f/255.0f, 74.0f/255.0f, 1.00f);

    const ImVec4 textPrimary   = ImVec4(236.0f/255.0f, 238.0f/255.0f, 244.0f/255.0f, 1.00f);
    const ImVec4 textSecondary = ImVec4(155.0f/255.0f, 161.0f/255.0f, 175.0f/255.0f, 1.00f);
    const ImVec4 textDisabled  = ImVec4(95.0f/255.0f,  101.0f/255.0f, 114.0f/255.0f, 1.00f);

    const ImVec4 accentPrimary = ImVec4(78.0f/255.0f, 117.0f/255.0f, 255.0f/255.0f, 1.00f);
    const ImVec4 accentHover   = ImVec4(98.0f/255.0f, 134.0f/255.0f, 255.0f/255.0f, 1.00f);
    const ImVec4 accentDim     = ImVec4(38.0f/255.0f, 56.0f/255.0f, 120.0f/255.0f, 1.00f);

    colors[ImGuiCol_Text]                  = textPrimary;
    colors[ImGuiCol_TextDisabled]          = textDisabled;
    colors[ImGuiCol_WindowBg]              = bgBase;
    colors[ImGuiCol_ChildBg]               = bgSurface;
    colors[ImGuiCol_PopupBg]               = ImVec4(22.0f/255.0f, 24.0f/255.0f, 31.0f/255.0f, 0.98f);
    colors[ImGuiCol_Border]                = borderSubtle;
    colors[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]               = bgWidget;
    colors[ImGuiCol_FrameBgHovered]        = bgHover;
    colors[ImGuiCol_FrameBgActive]         = bgActive;
    colors[ImGuiCol_TitleBg]               = bgBase;
    colors[ImGuiCol_TitleBgActive]         = bgSurface;
    colors[ImGuiCol_TitleBgCollapsed]      = bgBase;
    colors[ImGuiCol_MenuBarBg]             = bgSurface;
    colors[ImGuiCol_ScrollbarBg]           = ImVec4(18.0f/255.0f, 20.0f/255.0f, 25.0f/255.0f, 0.60f);
    colors[ImGuiCol_ScrollbarGrab]         = borderStrong;
    colors[ImGuiCol_ScrollbarGrabHovered]  = accentDim;
    colors[ImGuiCol_ScrollbarGrabActive]   = accentPrimary;
    colors[ImGuiCol_CheckMark]             = accentPrimary;
    colors[ImGuiCol_SliderGrab]            = accentPrimary;
    colors[ImGuiCol_SliderGrabActive]      = accentHover;
    colors[ImGuiCol_Button]                = bgWidget;
    colors[ImGuiCol_ButtonHovered]         = bgHover;
    colors[ImGuiCol_ButtonActive]          = bgActive;
    colors[ImGuiCol_Header]                = ImVec4(32.0f/255.0f, 38.0f/255.0f, 52.0f/255.0f, 1.00f);
    colors[ImGuiCol_HeaderHovered]         = ImVec4(42.0f/255.0f, 50.0f/255.0f, 68.0f/255.0f, 1.00f);
    colors[ImGuiCol_HeaderActive]          = ImVec4(52.0f/255.0f, 62.0f/255.0f, 85.0f/255.0f, 1.00f);
    colors[ImGuiCol_Separator]             = borderSubtle;
    colors[ImGuiCol_SeparatorHovered]      = borderStrong;
    colors[ImGuiCol_SeparatorActive]       = accentPrimary;
    colors[ImGuiCol_ResizeGrip]            = ImVec4(40.0f/255.0f, 44.0f/255.0f, 56.0f/255.0f, 0.35f);
    colors[ImGuiCol_ResizeGripHovered]     = borderStrong;
    colors[ImGuiCol_ResizeGripActive]      = accentPrimary;
    colors[ImGuiCol_Tab]                   = bgSurface;
    colors[ImGuiCol_TabHovered]            = bgHover;
    colors[ImGuiCol_TabSelected]           = ImVec4(30.0f/255.0f, 35.0f/255.0f, 48.0f/255.0f, 1.00f);
    colors[ImGuiCol_TabDimmed]             = bgBase;
    colors[ImGuiCol_DockingPreview]        = ImVec4(78.0f/255.0f, 117.0f/255.0f, 255.0f/255.0f, 0.40f);
    colors[ImGuiCol_DockingEmptyBg]        = bgBase;
    colors[ImGuiCol_PlotLines]             = accentPrimary;
    colors[ImGuiCol_PlotLinesHovered]      = accentHover;
    colors[ImGuiCol_PlotHistogram]         = accentPrimary;
    colors[ImGuiCol_PlotHistogramHovered]  = accentHover;
    colors[ImGuiCol_TableHeaderBg]         = bgSurface;
    colors[ImGuiCol_TableBorderStrong]     = borderSubtle;
    colors[ImGuiCol_TableBorderLight]      = borderSubtle;
    colors[ImGuiCol_TableRowBg]            = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]         = ImVec4(24.0f/255.0f, 26.0f/255.0f, 33.0f/255.0f, 0.50f);
    colors[ImGuiCol_TextSelectedBg]        = ImVec4(78.0f/255.0f, 117.0f/255.0f, 255.0f/255.0f, 0.35f);
    colors[ImGuiCol_DragDropTarget]        = accentPrimary;
    colors[ImGuiCol_NavHighlight]          = accentPrimary;
    colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.00f, 1.00f, 1.00f, 0.15f);
    colors[ImGuiCol_NavWindowingDimBg]     = ImVec4(0.00f, 0.00f, 0.00f, 0.55f);
    colors[ImGuiCol_ModalWindowDimBg]      = ImVec4(0.00f, 0.00f, 0.00f, 0.65f);
}

} // namespace openreverse
