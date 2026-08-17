# OpenReverse technical debt

Last updated: 2026-08-17

## Analysis accuracy

- DIA/PDB ingestion is optional and local. Symbol-server discovery/download,
  source information, templates, and more complex DIA type relationships are
  not implemented.
- Register-origin propagation merges simple CFG predecessor states and bounded
  direct-call return evidence. It intentionally does not claim SSA, general
  alias/points-to analysis, heap-object identity, or whole-program propagation.
- Runtime functions and validated symbol ranges provide strong x64 boundaries.
  x86 boundaries, indirect call/jump targets, tail calls, exception-flow edges,
  and optimized code without metadata remain incomplete. Prologue scanning is
  a bounded heuristic fallback.
- Raw snapshots without PE sections conservatively expose one synthetic
  readable/writable/executable range. Sparse minidumps can be rejected when
  selected-module headers or required ranges are absent.
- The PE relocation directory is not yet ingested into the shared signature
  pipeline. UTF-16 and cross-block string recovery remain limited.
- Structure candidates group compatible field evidence but are not recovered
  source-language types. Symbol-derived types retain explicit provenance.

## Version Intelligence and performance

- Algorithm v2 uses staged indexes and per-function/total comparison budgets,
  but whole-program assignment, dominators, full loop equivalence, indirect-call
  neighborhoods, and compiler-aware semantic equivalence are not implemented.
- Old dump projects are not accepted as comparison inputs.
- Signature results are cached per comparison, but large-module generation and
  uniqueness evaluation still deserve profiling before a multi-pattern engine.
- Executable bytes are decoded for broad discovery and again for bounded
  per-function CFGs. A shared immutable decode cache should be added only after
  corpus timings prove the memory/performance tradeoff.
- Stage timings and the local JSON corpus tool exist, but no committed benchmark
  baseline is appropriate until a legally redistributable representative
  corpus and stable runner are selected.

## State and architecture

- `Application` remains a broad composition root. Target lifecycle,
  project/workspace coordination, and navigation are the next coherent
  extraction candidates; an arbitrary manager-class rewrite is not planned.
- `AnalysisDatabase` is canonical. `Application::stringResults` and the
  compatibility `XRefScanner` mirror the most recently published snapshot for
  unmigrated panels and should be removed incrementally.
- `AnalysisTargetKind` is explicit, but some view availability checks still use
  `isAttached` to mean that any target is open.
- Database indexes cover functions, Xrefs, strings, and globals. Version
  Intelligence builds one-pass field/import/signature context and candidate
  indexes per comparison. Add persistent indexes only for measured consumers.
- Extension ABI v1 exposes bounded target/function snapshots, not the complete
  CFG/data model. Native extensions are trusted in-process code and are not
  sandboxed; out-of-process isolation requires a separate threat model.

## UI and Windows integration

- The layered CFG is navigable and bounded, but lacks manual node placement,
  persistence, minimap, advanced edge routing, and full rendering above 512
  blocks.
- Native dialogs, docking, DPI combinations, device-loss recovery, and the CFG
  visual result require manual Windows regression passes; pixel automation is
  intentionally not attempted.
- Core touched paths are Unicode/long-path aware. Future Win32 additions must
  continue using wide APIs and dynamic buffers.
- The combined GUI/CLI executable uses the Windows GUI subsystem, so automation
  must wait explicitly for reliable exit codes.

## Testing, packaging, and release

- Release and Debug CTest cover core, auth, static-open, and corpus workflows.
  Target switching through the full desktop event loop and native dialogs is
  not automated.
- The deterministic mutation corpus is not a coverage-guided long-running
  fuzzer. MSVC AddressSanitizer is not a default CI job; optional MSVC
  `/analyze` is available through CMake.
- A controlled fixture validates the corpus tool, but a documented broader
  redistributable corpus run is still required before public beta.
- Installer compilation is automated; install/launch/uninstall behavior still
  requires a manual clean-VM pass.
- The optional WorkOS flow still needs legitimate provider configuration and a
  live end-to-end verification. Community analysis remains usable signed out.
- Authenticode signing, signed update manifests, rollback, and WinGet metadata
  remain pending a legitimate release process. No signing is simulated.
