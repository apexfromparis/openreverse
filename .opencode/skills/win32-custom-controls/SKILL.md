---
name: win32-custom-controls
description: Use when implementing custom Win32 GDI owner-drawn controls, double-buffered canvas rendering, badges, tabs, and flicker-free drawing.
---

# Win32 Custom Controls & Flicker-Free Rendering

## 1. Zero-Flicker Double Buffering
- Never draw directly to the window client DC during `WM_PAINT`.
- Always create a memory buffer DC (`CreateCompatibleDC`), create a bitmap (`CreateCompatibleBitmap`), draw all background and UI elements to the buffer, and copy in one shot via `BitBlt(dc, 0, 0, width, height, buffer, 0, 0, SRCCOPY)`.
- Release all GDI objects (`DeleteObject`, `DeleteDC`) to avoid GDI handle leaks.

## 2. Styled Pill Badges & Tabs
- Draw custom rounded pill badges using `RoundRect(dc, left, top, right, bottom, 6, 6)`.
- Use high-contrast foreground text over tinted background brushes.
- For active navigation tabs, render a glowing accent bar (`FillRect` with Cyber Cyan or Purple) on the left or bottom edge.

## 3. Custom Button Hierarchy
- **Primary Action Buttons**: Cyber Cyan background (`RGB(0, 229, 255)`) with dark text (`RGB(8, 23, 24)`), bold font.
- **Secondary / Toggle Buttons**: Elevated slate background (`RGB(31, 38, 51)`), brightening on hover.
- **Danger Action Buttons**: Coral background (`RGB(255, 82, 82)`) with white text.
