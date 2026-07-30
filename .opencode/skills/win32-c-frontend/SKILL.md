---
name: win32-c-frontend
description: Use when building or changing the native C/Win32 frontend, windows, controls, painting, input handling, themes, or responsive desktop layout in Powerfull IDA.
---

# Win32 C Frontend

- Keep the UI native, dependency-light, and compatible with MSVC.
- Separate drawing, input, state, and backend boundaries even when the first implementation is a single C file.
- Use DPI-aware sizing, keyboard navigation, clear hit targets, and resize-safe layout calculations.
- Preserve the dark forensic-workbench visual language: dense information layout, readable monospace code, restrained accent colors.
- Avoid blocking the UI thread with analysis, file loading, or AI requests; use worker threads and message-based updates.
- Validate all Win32 handles and clean up GDI objects, fonts, brushes, and file dialogs.
- Compile with warnings enabled and test both the initial window and resized states.
