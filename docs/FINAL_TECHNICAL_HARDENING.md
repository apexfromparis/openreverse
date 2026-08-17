# Final technical hardening

Last updated: 2026-08-17

This pass started from `7a947373a723a4a30e1f71b34e331112a9512602`.
The baseline Release build, installer, two CTest tests, and CLI smoke tests were
green before implementation. Unrelated local commercial documents and a
screenshot remained untracked and were not modified or staged.

## Closed findings

### P0 — correctness and security

- Removed the hidden `--decompile-exe`/`--decompile-pid` path that launched a
  supplied executable under a misleading static-analysis name. No public CLI
  analysis command calls `CreateProcess`.
- Added a regression sentinel proving that normal and Unicode-path `open`
  workflows do not execute the analyzed fixture. The removed legacy command is
  also checked for fail-closed behavior.
- Added checked Direct3D device/swap-chain/render-target/resize/present and
  Win32 window initialization failure paths.
- Kept binary, dump, project, and corpus input handling parser-only. Offline
  targets are never loaded as executable modules.

### P1 — analysis quality

- Centralized control-flow classification in a Capstone ID/group and operand
  metadata helper. Function/CFG/data analysis no longer maintains separate
  mnemonic allowlists for calls, jumps, returns, or traps.
- The mapped and live module pipelines now publish a bounded CFG for each
  analyzed function. Discovery provenance distinguishes runtime functions,
  symbols, exports, entry points, direct calls, traversal, and heuristic seeds.
- Added an optional DIA implementation that validates PE CodeView GUID/age,
  reads public/function symbols and boundaries, and imports structures, fields,
  and enums. A controlled MSVC fixture verifies identity and type data when the
  DIA SDK is installed.
- Added deterministic predecessor-state merging for register origins. Agreed
  Windows x64 argument origins cross blocks; conflicting merges become
  ambiguous. Direct-call return origins are bounded and field evidence retains
  block, instruction, base/index/scale/displacement/width/access, origin, and
  merge provenance.
- Version Intelligence algorithm v2 adds ordered instruction n-grams, ordered
  block hashes, typed CFG neighborhoods, symbol names, staged indexes, bounded
  candidate work, and signature-scan reuse. V1 project decisions remain
  readable. False-order, ambiguity, and 1,500-function scaling fixtures cover
  the new behavior.
- Added deterministic truncation/mutation loops for PE, project, and extension
  manifest parsers. Existing pattern, auth callback, and project limit tests
  remain active.

### P2 — architecture, performance, and Windows behavior

- `AnalysisDatabase` is the canonical published function/CFG/Xref/string/data
  state. `AnalysisPanel` no longer owns a function collection, and CLI queries
  the database/session rather than UI panels or ImGui state.
- `Application` now owns one explicit analysis publication path used by desktop
  and CLI workflows. The remaining `stringResults`/`XRefScanner` mirrors are
  compatibility caches for panels not yet migrated, not alternate analysis
  producers.
- Replaced the recursive source glob with explicit `OpenReverseCore`,
  `OpenReverseAuth`, `OpenReverseExtensions`, `OpenReverseUI`, vendor editor,
  application, and validation targets. Tests link reusable libraries.
- First-party targets compile at `/W4`; vendored ImGui/editor code is excluded
  from that policy. An opt-in `OPENREVERSE_ENABLE_MSVC_ANALYZE` switch enables
  MSVC code analysis without making normal CI dependent on tool-version noise.
- CI and local presets build and test Release and Debug.
- Touched file dialogs, PE loading, process/module discovery, dump export, and
  comparison/offset paths use wide Win32 APIs, UTF-8 conversion, dynamic
  buffers, or `std::filesystem::path`. The application manifest opts into long
  paths and UTF-8 active code page behavior.
- Analysis results expose code/discovery, CFG, data/structures, strings,
  signatures, and total stage durations.
- `OpenReverseValidation` recursively analyzes a user-supplied PE directory
  without executing files and writes bounded JSON records containing relative
  paths, raw-file SHA-256, architecture, counts, budgets, errors, and timings.
  Reports are ignored by Git.

### P3/P4 — product and engineering quality

- Replaced the vertical CFG-card list with a cached layered graph. It renders
  typed colored edges and arrowheads, entry/exit block styling, instructions,
  zoom, pan, fit, and click navigation. Rendering is bounded to 512 visible
  nodes with an explicit truncation notice.
- Removed sortable flags from Functions and Memory Map until real sort-spec
  handling exists.
- Consolidated first-party UTF-8/wide helpers and removed touched unsafe
  fixed-buffer copies and warning sources.

## Validation added

- `OpenReverse.Core`: deterministic core, DIA fixture, Version Intelligence,
  persistence, extension lifecycle, parser mutations, and scaling checks.
- `OpenReverse.Auth`: offline authentication security/state tests.
- `OpenReverse.StaticOpen`: normal and Unicode static-open execution sentinel.
- `OpenReverse.CorpusValidation`: valid Unicode-path PE plus malformed PE,
  machine-readable report, timings, hash, and no-execution sentinel.

## Remaining limitations

- `Application` remains a broad composition root; target lifecycle and
  navigation are coherent future extraction boundaries.
- Some UI consumers still read compatibility Xref/string caches. Their source
  is the canonical published result, but removing them requires panel-by-panel
  migration.
- The CFG layout is deterministic and interactive but not a full graph editor;
  very large functions are deliberately truncated for rendering.
- DIA is optional and requires a compatible DIA runtime. PDB download/symbol
  server policy is not implemented.
- Data flow is conservative, bounded origin propagation, not SSA, general
  alias analysis, or whole-program interprocedural analysis.
- The controlled corpus proves the workflow. A representative external
  open-source/Windows binary corpus still needs repeatable beta-candidate runs.
- Automated tests do not drive native dialogs, inspect ImGui pixels, or perform
  a complete installer install/uninstall cycle.
- MSVC AddressSanitizer was not made a default CI job; the Debug build,
  deterministic mutation corpus, parser budgets, and optional `/analyze` path
  are the stable Windows checks in this pass.
- Authenticode signing and signed update/rollback infrastructure remain pending
  legitimate release credentials and are not simulated.

## Release-readiness recommendation

**NOT READY FOR PUBLIC BETA.** Core automated gates are green, but a beta build
should not be published until the new CFG/file workflows receive a manual
Windows UI pass, the installer is exercised through install/launch/uninstall,
and the validator completes on a documented representative redistributable
binary corpus without unexplained failures or budget regressions.

This pass intentionally does not implement Stripe, billing, subscriptions,
entitlements, licenses, hosted AI, a commercial backend, private Pro code,
anti-cheat/protected-process bypasses, a release tag, or a GitHub Release.
