#pragma once

#include <imgui.h>
#include <string>

struct ImFont;

namespace openreverse {
namespace workspace_ui {

void ApplyTheme();

ImFont* GetMonoFont();
ImFont* GetDefaultFont();

bool EmptyState(const char* message);
void PanelHeader(const char* title, const char* context = nullptr);
void SectionLabel(const char* label, const char* value = nullptr);
void ToolbarSeparator();
void BeginToolbar();
void EndToolbar();

// Modern Product UI Design System
void CardBegin(const char* id, const ImVec2& size = ImVec2(0.0f, 0.0f), bool interactive = false);
void CardEnd();

bool NavItem(const char* id, const char* label, const char* iconText, bool active, float width = 0.0f);
void Badge(const char* text, ImU32 bgCol, ImU32 textCol);
bool PrimaryButton(const char* label, const ImVec2& size = ImVec2(0.0f, 0.0f));
bool SecondaryButton(const char* label, const ImVec2& size = ImVec2(0.0f, 0.0f));
void AvatarCircle(const ImVec2& center, float radius, const char* initials, ImU32 bgCol = 0, ImU32 textCol = 0);
void TextMuted(const char* text);
void TextHeading(const char* text, int level = 1);

} // namespace workspace_ui
} // namespace openreverse
