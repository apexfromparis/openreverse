---
name: interactive-disassembly-ui
description: Use when building interactive disassembly views, syntax highlighting, XREF badges, breakpoint gutters, and keyboard navigation in reverse engineering GUIs.
---

# Interactive Disassembly UI

## 1. Syntax Highlighting Token Colors
- **Addresses / Offsets**: Muted slate (`RGB(133, 148, 169)`).
- **Mnemonics (Flow Control: jmp, call, ret, jz)**: Coral / Amber (`RGB(255, 171, 64)`).
- **Mnemonics (Arithmetic / Logic: add, sub, xor, test)**: Synthwave Purple (`RGB(187, 134, 252)`).
- **Mnemonics (Memory: mov, lea, push, pop)**: Cyber Cyan (`RGB(0, 229, 255)`).
- **Registers (rax, rbp, rsp, rcx)**: Bright Cyan / Purple accent.
- **Comments (`; ...`)**: Green-gray italic style (`RGB(100, 160, 120)`).

## 2. Interactive Columns & Gutter
- **Breakpoint Gutter**: A 24px left gutter where clicking toggles a red glowing breakpoint circle.
- **XREF Badges**: Render small interactive pills next to function headers (e.g., `[XREF: 3 Callers]`).
- **Row Selection & Hover**: Current line has a dark slate highlight with a bright left accent indicator.

## 3. Keyboard Shortcuts & Navigation
- **`Space`**: Toggle between Linear Disassembly View and Control Flow Graph View.
- **`F5`**: Execute full binary analysis / decompile.
- **`F1`**: Toggle AI Copilot & Decompiler side panel.
- **`G`**: Open "Jump to Address" modal.
