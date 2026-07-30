---
name: micro-animations-win32
description: Use when adding smooth hover transitions, pulsing status dots, animated progress bars, and glowing interactive feedback to Win32 C applications.
---

# Win32 Micro-Animations & Dynamic Visual Feedback

## 1. Pulse & Blinking Indicators
- Implement a lightweight timer (`WM_TIMER` at 250ms or 500ms) to update animation step counters.
- Use a pulsing online status dot for the AI engine or binary analysis state: toggle or smoothly interpolate between bright emerald (`RGB(0, 255, 128)`) and muted emerald (`RGB(0, 140, 70)`).

## 2. Interactive Hover Transitions
- Track `hover_target` in `WM_MOUSEMOVE` and invalidate only when the hovered control ID changes.
- Highlight hovered buttons, rows, and graph nodes instantly with elevated brightness and sleek borders.
- Show tooltip-like inline description messages in the status bar whenever the mouse moves over an interactive element.

## 3. "Donne Envie" Interactive Wow-Factor
- Ensure every clickable element responds visibly to hover and click events.
- Display a dynamic entropy or memory progress bar with gradient-like multi-colored segments.
- Add visual flair like a glowing Matrix/Cyberpunk title icon in the top-left sidebar.
