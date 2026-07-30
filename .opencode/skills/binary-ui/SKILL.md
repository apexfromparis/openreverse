---
name: binary-ui
description: Use when designing views for disassembly, hex, strings, imports, symbols, graphs, memory maps, logs, or synchronized binary-analysis panels.
---

# Binary Analysis UI

- Keep address, bytes, mnemonic, operands, and comments aligned in a stable monospace grid.
- Support selection, keyboard navigation, copy, follow-jump, search, and synchronized scrolling.
- Use clear visual states for code, data, unknown bytes, warnings, user names, and AI suggestions.
- Never hide analysis uncertainty; show confidence and provenance where relevant.
- Virtualize large lists and graphs so opening a large binary does not freeze the interface.
- Keep panel state independent from the engine so layouts can be restored safely.
