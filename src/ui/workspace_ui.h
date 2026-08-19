#pragma once

struct ImFont;

namespace openreverse {
namespace workspace_ui {

void ApplyTheme();

ImFont* GetMonoFont();

bool EmptyState(const char* message);
void PanelHeader(const char* title, const char* context = nullptr);
void SectionLabel(const char* label, const char* value = nullptr);
void ToolbarSeparator();
void BeginToolbar();
void EndToolbar();

} // namespace workspace_ui
} // namespace openreverse
