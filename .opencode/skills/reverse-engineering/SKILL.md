---
name: reverse-engineering
description: Use when implementing binary loading, PE/ELF parsing, disassembly, x86/x64 instruction analysis, symbols, strings, imports, functions, or control-flow graphs for Powerfull IDA.
---

# Reverse Engineering

- Treat every binary as hostile input and never assume headers, offsets, sizes, or strings are valid.
- Keep file offsets, virtual addresses, image bases, sections, and permissions explicit in data structures.
- Bounds-check every read and use checked arithmetic before adding offsets or lengths.
- Make architecture and endianness explicit; do not silently decode an unsupported format.
- Preserve raw bytes and provenance for every decoded instruction so UI annotations can be audited.
- Design analysis passes as deterministic, cancellable stages: load, map, decode, discover functions, resolve references, render.
- Keep parsing and analysis separate from the UI so the engine can be tested without a window.
