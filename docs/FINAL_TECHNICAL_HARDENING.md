# Final technical hardening

Last verified against `7a947373a723a4a30e1f71b34e331112a9512602` on
2026-08-17. This document records only issues confirmed in the current source;
it is updated as the hardening pass closes them.

## Baseline

- Windows x64 Release configure/build: passed.
- Installer `OpenReverse-2.0.0-Setup.exe`: built.
- Release CTest: 2/2 passed.
- CLI `--help`, `--version`, and static `open` fixture smoke tests: passed.
- `HEAD` matched `origin/main`; four unrelated local documentation/screenshot
  files were untracked and are intentionally excluded from this work.

## P0 — correctness / security

- `src/main.cpp` exposes a hidden `--decompile-exe` path that launches the
  supplied executable before attaching. Its name falsely suggests static
  analysis, and it passes a casted `std::string::c_str()` to mutable
  `CreateProcessA` storage.
- Static `open`, dump, and project paths are implemented as parsers/loaders, but
  the invariant is not protected by an integration regression that detects
  accidental target execution.
- The D3D render-target, resize, presentation, window-class, and window-creation
  paths ignore important HRESULT/Win32 failures and may dereference a missing
  back buffer after device loss or initialization failure.

## P1 — analysis quality

- Control-flow semantics are duplicated as mnemonic-string comparisons in
  `Disassembler`, `FunctionAnalyzer`, and `DataAnalyzer`, despite Capstone IDs
  and groups already being retained.
- `ModuleAnalyzer` publishes discovered function records without computing
  their CFGs. Only the selected UI/CLI function is analyzed on demand, so the
  canonical database and Version Intelligence often see empty instruction and
  CFG evidence.
- `ISymbolProvider` has no concrete implementation. PE CodeView identity is not
  parsed, DIA symbols/types are not ingested, and the controlled fixture PDB is
  not validated. The installed Visual Studio Build Tools includes the DIA SDK,
  so there is no local external blocker.
- Register-origin propagation is linear within a section-wide instruction
  stream. It neither starts from CFG predecessors nor rejects conflicting merge
  origins explicitly. Field evidence therefore cannot distinguish stable
  inter-block provenance from a coincidental linear decode.
- Version Intelligence compares an instruction multiset plus one whole-function
  ordered hash, but has no local ordered n-gram/block sequence evidence. Its
  context builder repeatedly scans whole Xref/string/global/signature/field
  collections for every function.
- Signature migration evaluates each pattern independently against the new
  image; no per-comparison scan result cache is shared.
- Parser tests cover many malformed PE/project cases, but there is no dedicated
  deterministic malformed-input corpus runner or fuzz/sanitizer job.

## P2 — architecture / performance

- `AnalysisDatabase` is nominally canonical, while `AnalysisPanel`,
  `stringResults`, and `XRefScanner` retain authoritative-looking mirrors.
  Several CLI commands still read or trigger analysis through `AnalysisPanel`.
- `Application` still owns target lifecycle, dialogs, project orchestration,
  analysis publication, CLI-facing services, extension services, navigation,
  and all panels.
- CMake recursively globs all application sources and recompiles the same core
  and authentication sources directly into test executables instead of using
  explicit reusable first-party libraries.
- Touched open/save and PE-loading workflows use ANSI APIs and fixed
  `MAX_PATH` buffers, so valid Unicode and long paths are not consistently
  supported.
- Stage durations exist in `ModuleAnalysisResult`, but no machine-readable
  validation report records counts, truncation, failures, and timings across a
  local corpus.
- CI builds/tests Release only, does not compile first-party code at `/W4`, and
  has no Debug or practical static-analysis validation.

## P3 — product / UX

- The CFG workspace is a list of edges and basic-block cards, not a spatial,
  cached, pannable/zoomable graph.
- At least the Functions and Memory Map tables declare
  `ImGuiTableFlags_Sortable` without consuming `ImGuiTableSortSpecs`.
- Function navigation recomputes selected CFGs rather than using canonical
  cached analysis, creating avoidable latency and inconsistent evidence.

## P4 — engineering polish

- Touched Win32 conversion/file-dialog code duplicates ANSI/UTF conversion and
  fixed-buffer handling.
- Technical-debt, architecture, pipeline, Version Intelligence, building, and
  release-readiness documentation must be reconciled after implementation.

## Explicit scope exclusions

This pass does not implement billing, Stripe, subscriptions, entitlements,
licenses, hosted AI, a commercial backend, private Pro code, protected-process
bypasses, anti-cheat bypasses, kernel drivers, stealth injection, or release
publication/signing.
