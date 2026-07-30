#pragma once
// ============================================================================
// KYV - UI Manager
// Theme, fonts, shared UI helpers
// ============================================================================

struct ImFont;

namespace kyv {

class UIManager {
public:
    static void ApplyTheme();

    // Monospace font for addresses, hex, disasm (optional - use after ApplyTheme)
    static ImFont* GetMonoFont();

    // Shared UI: empty state when no process attached
    static bool EmptyState(const char* message);
    // Toolbar: vertical separator
    static void ToolbarSeparator();
    // Compact spacing for toolbar rows
    static void BeginToolbar();
    static void EndToolbar();
};

} // namespace kyv
