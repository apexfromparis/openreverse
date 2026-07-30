---
name: secure-c
description: Use when writing or reviewing C code involving binary parsing, memory, strings, file I/O, dynamic libraries, threads, or security-sensitive application behavior.
---

# Secure C

- Prefer explicit sizes, fixed-width integer types, and checked allocation and arithmetic.
- Reject malformed input early; never continue after a truncated header or failed allocation.
- Avoid unbounded string APIs and make truncation behavior intentional.
- Track ownership for every allocation, handle, mapping, thread, and plugin instance.
- Avoid executing or loading analyzed content by default; analysis must be read-only unless explicitly requested.
- Use least privilege, optional sandboxing, and process isolation for risky plugins or emulation.
- Compile with `/W4`, security checks, and sanitizers or verifier tools where available; review warnings instead of suppressing them.
