---
name: cfg-graph-ui
description: Use when rendering Control Flow Graphs (CFG), basic block diagrams, branch arrows, and visual disassembly nodes in Powerfull IDA.
---

# Control Flow Graph (CFG) Visual Renderer

## 1. Basic Block Cards
- Render each basic block as a styled, rounded card (`RoundRect` with radius 8px):
  - **Header Banner**: Address and block label (e.g., `BLOCK 0x00401000 - Entry Point`) with distinct background tint.
  - **Instruction List**: Monospace instructions rendered cleanly inside the card body.
  - **Card Borders**: Active block has a glowing Cyber Cyan border; standard blocks have a sleek border (`RGB(43, 52, 68)`).

## 2. Branch Connections & Arrow Styling
- Connect basic blocks with colored flow lines:
  - **True / Taken Conditional Jump**: Emerald Green line (`RGB(0, 230, 118)`).
  - **False / Not-Taken Conditional Jump**: Coral Red line (`RGB(255, 82, 82)`).
  - **Unconditional Jump (`jmp`, `call`)**: Cyber Cyan line (`RGB(0, 229, 255)`).
- Provide visual arrowheads at the destination block header.

## 3. Interactive Navigation
- Support clicking on block headers or jump instructions to follow targets instantly.
- Highlight incoming and outgoing edges when hovering over a basic block card.
