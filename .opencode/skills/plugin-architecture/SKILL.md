---
name: plugin-architecture
description: Use when designing or implementing Powerfull IDA plugins, DLL loading, plugin APIs, lifecycle management, extension points, or plugin isolation.
---

# Plugin Architecture

- Define a small versioned C ABI with explicit struct sizes and capability flags.
- Never expose private engine structs across the DLL boundary; use opaque handles and callbacks.
- Validate plugin metadata before loading and reject incompatible ABI versions.
- Make init, shutdown, reload, errors, and cancellation explicit lifecycle states.
- Keep plugin work off the UI thread and prevent callbacks after unload.
- Prefer out-of-process execution for untrusted third-party plugins.
- Provide logging, permissions, timeouts, and a way to disable a plugin without deleting project data.
