---
name: cyberpunk-theme-design
description: Use when applying premium dark cyberpunk, neon-accented, glassmorphic, and high-contrast visual aesthetics to Powerfull IDA frontend components.
---

# Cyberpunk & High-Tech Visual Theme System

## 1. Color Palette & Dark Obsidian Matrix
- **Obsidian Base (`C_BG`)**: `RGB(10, 12, 16)` — Deepest background for workspace frame.
- **Surface Sidebar (`C_SIDEBAR`)**: `RGB(15, 18, 25)` — Sleek dark slate for navigation and tools.
- **Panel Base (`C_PANEL`)**: `RGB(20, 24, 34)` — Elevated surface for cards, views, and inspector panes.
- **Interactive Card (`C_PANEL_RAISED`)**: `RGB(28, 35, 49)` — Active hover or selected surface.
- **Neon Cyber Cyan (`C_CYAN`)**: `RGB(0, 229, 255)` — Primary brand accent, active tabs, jump targets.
- **Synthwave Purple (`C_PURPLE`)**: `RGB(187, 134, 252)` — AI copilot, registers, function calls, decompiler accents.
- **Matrix Emerald (`C_GREEN`)**: `RGB(0, 230, 118)` — Safe calls, true/taken branches, online status pulse.
- **Amber Warning (`C_ORANGE`)**: `RGB(255, 171, 64)` — Conditional flags, warnings, high entropy regions.
- **Coral Rose (`C_RED`)**: `RGB(255, 82, 82)` — Dangerous imports, breakpoints, false/not-taken branches.

## 2. Typography & Hierarchy
- Use crisp, high-legibility fonts: **Segoe UI** for UI labels, titles, and buttons; **Consolas** for assembly, hex dumps, and C pseudocode.
- Maintain strict size and weight hierarchy:
  - **Brand Title**: 18px Bold + Letter Spacing.
  - **Section Headings**: 16px Bold with subtle underline separators.
  - **Body / Labels**: 13px Regular with high-contrast text (`RGB(235, 240, 250)`).
  - **Muted / Subtitles**: 11px Regular with slate gray (`RGB(125, 140, 165)`).

## 3. Visual Polish & "Donne Envie" Principles
- **Glowing Accent Borders**: Highlight active views and selected rows with a 2px Cyber Cyan or Neon Purple left border accent.
- **Status Badges**: Display pill-shaped badges (e.g. `[x64]`, `[HIGH RISK]`, `[AI ONLINE]`) with tinted background boxes and bright text.
- **Clean Dividers**: Use subtle 1px border lines (`RGB(38, 46, 62)`) to separate functional panes without clutter.
