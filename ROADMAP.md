# OpenReverse roadmap

This roadmap records direction, not deadlines. Experimental results remain
subject to change until their analysis models stabilize.

## Shipped

- Raw PE, RVA-mapped image, user dump, and authorized live-process address spaces
- Static mapped-module, raw-snapshot, and captured minidump-module analysis
- x86/x64 decoding, x64 runtime-function boundaries, function provenance, and CFGs
- Operand-level Xrefs, strings, RIP-relative globals, and field-access evidence
- Simple register-origin propagation for Windows x64 argument registers
- Typed offsets, SHA-256 module identity, safe JSON import/export, and C++ export
- Decoded-instruction signatures, target relationships, and uniqueness results
- Conservative function fingerprinting and migration ambiguity reporting
- Indexed canonical analysis snapshots with bounded scheduling and cancellation
- Versioned `.orev` project save/load with target verification, annotations,
  bookmarks, structures, offsets, signatures, and UI/session restoration
- Experimental indexed old/new Version Intelligence review with structured
  evidence, explicit ambiguity, typed migrations, and persisted user decisions
- Native Windows workspace, command shell, installer, and optional AI client
- Versioned Windows x64 native extension ABI, bounded manifest discovery,
  controlled Community host APIs, extension-owned project state, compatibility
  tests, and a standalone SDK example

## In progress

- Moving the remaining panel compatibility views and CLI queries directly onto
  `AnalysisDatabase`
- Profiling and extending Version Intelligence to old dump projects, indirect
  call neighborhoods, and symbol-enriched comparison evidence
- Adding application and UI-level regression coverage

## Planned

- A DIA-backed `ISymbolProvider` for PDB functions, public symbols, and types
- Predecessor-aware and interprocedural data flow, alias analysis, and indirect
  target recovery
- PE relocation-directory ingestion for signature wildcard provenance
- Configurable AI context levels and persistent provider preferences

## Research

- Evidence-based structure merging across functions and call sites
- Deterministic spatial CFG layout for large functions
- Out-of-process extension hosting, RPC isolation, process restrictions, and
  signed extension distribution
