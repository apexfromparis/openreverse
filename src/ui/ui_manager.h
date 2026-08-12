#pragma once

struct ImFont;

namespace openreverse {

class UIManager {
public:
    static void ApplyTheme();

    static ImFont* GetMonoFont();

    static bool EmptyState(const char* message);
    static void PanelHeader(const char* title, const char* context = nullptr);
    static void SectionLabel(const char* label, const char* value = nullptr);
    static void ToolbarSeparator();
    static void BeginToolbar();
    static void EndToolbar();
};

} // namespace openreverse
