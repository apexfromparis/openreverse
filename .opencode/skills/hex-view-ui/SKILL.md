---
name: hex-view-ui
description: Use when designing or building hex editors, memory dumps, ASCII sidebars, entropy heatmaps, and byte inspectors in reverse engineering tools.
---

# Hex View & Memory Entropy UI

## 1. Hexdump Grid Layout
- Display a classic 16-byte hex matrix per line:
  - **Address Gutter**: Monospace hex offset (e.g., `00401000`) in muted gray.
  - **Hex Bytes Column**: 16 hexadecimal byte pairs separated by spaces, with an extra gap after byte 7 for visual grouping.
  - **ASCII Column**: 16 characters representing printable ASCII bytes (`32` to `126`) or a dot `.` for non-printable characters.

## 2. Color Coding Bytes
- **Zeroes (`00`)**: Very muted dark slate (`RGB(65, 75, 95)`) to let real data stand out.
- **ASCII Text**: Highlight in Cyan (`C_CYAN`) when part of readable strings.
- **Pointers / References**: Highlight in Purple (`C_PURPLE`) when matching loaded section addresses.
- **Selected Range**: Fill background with `RGB(28, 53, 58)` and draw bright border.

## 3. Entropy Heatmap Bar
- Display an entropy spectrum bar above the hex dump:
  - **Low Entropy (0.0 - 4.0)**: Blue / Cyan (standard uncompressed code/data).
  - **Medium Entropy (4.0 - 6.8)**: Green / Purple (structured data, tables).
  - **High Entropy (6.8 - 8.0)**: Amber / Red (packed, encrypted, or compressed sections).
