# OpenReverse roadmap

This roadmap records direction, not deadlines. Experimental results remain
subject to change until their analysis models stabilize.

## Shipped

- Offline PE32/PE32+ parsing and section-aware mapping
- Read-only live process and module inspection
- x86/x64 disassembly, function candidates, CFGs, and typed Xrefs
- String and wildcard pattern scanning
- Shared analysis snapshots with bounded scheduling and cancellation
- Hex, memory, structures, bookmarks, offsets, CLI, and optional AI workflows
- Native Windows installer and uninstall flow

## In progress

- Moving remaining panel-local compatibility data to `AnalysisDatabase`
- Improving offline analysis scheduling and explicit live/offline target state
- Strengthening regression coverage for application and UI workflows

## Planned

- Persistent `.orev` projects, names, comments, structures, and bookmarks
- PDB/symbol loading and richer import/type presentation
- Deeper data-flow analysis and indirect-target recovery
- Binary comparison and signature generation
- Configurable AI context levels and persistent provider preferences

## Research

- Evidence-based structure merging across functions and call sites
- Deterministic spatial CFG layout for large functions
- A stable, versioned extension API after core analysis models settle
