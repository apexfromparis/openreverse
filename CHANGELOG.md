# Changelog

Notable user-visible changes are documented here.

## 2.0.0-beta.1 - 2026-08-19

First public beta release of OpenReverse Community.

### Highlights

- **Offline-First Windows PE & Dump Analysis**: Full static analysis for PE32 and PE32+ (x86/x64) executables, DLLs, system drivers, mapped memory dumps, and captured minidumps without target execution.
- **Graphical Control-Flow Graphs (CFG)**: Layered graphical CFG with typed control flow edges (fallthrough, conditional true/false, unconditional jump, call, ret), interactive zoom, pan, fit, and synchronized address navigation.
- **Version Intelligence Workspace**: Review-first binary comparison and function matching across builds with sequence/CFG/symbol indexes, structured similarity metrics, deterministic change summaries, and offset/field migrations.
- **Projects & Extensions**: Unified `.orev` atomic project persistence and versioned C ABI native extension host with standalone Community SDK (`sdk/include/openreverse_extension.h`).
- **Optional Native Account Integration**: Optional Supabase Auth email/password login and Windows Credential Manager session persistence with authoritative server-side profile synchronization. Community analysis and local/BYOK AI remain 100% functional offline without an account.

### Analysis

- Capstone-powered instruction decoding and control-flow classification.
- Bounded function discovery via PE headers, `.pdata` runtime functions, exported symbols, call targets, and heuristic preambles.
- Deep cross-reference (Xref) indexing with operand classification (code calls, code jumps, data reads, data writes, address references).
- String and evidence scanning (ASCII, UTF-16LE, URLs, system paths, APIs) with category attribution.
- Global and field offset modeling with SHA-256 binary identity and JSON/C++ header export.
- Optional DIA / PDB ground truth symbol parsing with graceful fallback on missing or mismatched PDBs.

### Projects

- Atomic `.orev` file persistence saving target path, target SHA-256, custom offsets, bookmarks, and accepted Version Intelligence decisions.
- Safe handling of missing, moved, or modified targets with explicit status diagnostics.

### Version Intelligence

- Multi-stage indexed function matching (exact hash, instruction sequence, CFG topology, exported/debug symbols).
- Explicit ambiguity detection rather than false certainty.
- Signature and typed offset migration with reviewer accept/reject workflow.

### Extensions

- In-process versioned C ABI extension API v1 (`sdk/include/openreverse_extension.h`).
- Manifest validation with declared commands, panels, and custom `.orev` extension state namespaces.
- Structured diagnostics for missing dependencies, invalid entry points, or runtime callback failures.
- Example extension included in `examples/hello_extension`.

### Account

- Optional Supabase Auth integration supporting email/password sign-in and token rotation.
- Secure refresh token persistence via Windows Credential Manager (`OpenReverse.Account.Session`).
- Authoritative `/api/me` profile synchronization with fail-closed commercial tier detection.
- Complete isolation: network errors, unconfigured account services, or server outages never gate or impair Community functionality.

### Fixes & Hardening

- Ensured all static analysis, dump loading, project reopening, and corpus validation paths are non-executable.
- Enforced strict bounding on untrusted PE headers, section tables, and symbol streams to prevent memory exhaustion or access violations.
- Fixed uninstaller to cleanly remove shortcuts, registry entries, and program files from `%LocalAppData%\Programs\OpenReverse`.
- Handled Unicode and long Windows filesystem paths across all file dialogs and CLI commands.

### Known Limitations

- Heuristic function discovery may miss non-standard compiler emitted functions when debug metadata or `.pdata` is unavailable.
- Native extensions execute in-process and must be trusted by the user (not sandboxed).
- Deep interprocedural data-flow analysis is experimental.
- Binaries in this beta release are currently unsigned (Authenticode signing will be added in future releases).
