# OpenReverse technical debt

Last updated: 2026-08-17

## Analysis accuracy

- `ISymbolProvider` is an interface only. A DIA-backed Windows implementation,
  PDB GUID/age extraction, symbol functions, and type ingestion remain absent.
- Register-origin propagation is block-local and intentionally stops on
  ambiguous transforms. It does not perform predecessor merging,
  interprocedural propagation, alias/points-to analysis, or deterministic
  pointer-chain recovery.
- Runtime functions provide strong x64 boundaries, but x86 boundaries and
  indirect call/jump targets remain incomplete. Prologue scanning remains a
  bounded fallback.
- Raw snapshots without PE sections must conservatively expose one synthetic
  readable/writable/executable range. Users must interpret results as partial.
- Minidump analysis requires the selected module's headers and relevant ranges
  to be present in the dump. Sparse captures can be rejected even when module
  metadata exists.
- Signature generation can consume relocation RVAs, but the PE relocation
  directory is not yet ingested by the common pipeline.
- Global classification is section- and Xref-based. Import-thunk/vtable/constant
  semantics need stronger deterministic evidence before further subdivision.
- UTF-16 and cross-block string recovery remain limited.

## Migration and persistence

- The experimental Version Intelligence workspace compares a PE-backed old
  binary/project with the current offline target. Old dump projects, whole-
  program assignment optimization, indirect-call neighborhoods, and symbol-
  enriched matching remain absent.
- Versioned `.orev` projects persist target identity, annotations, bookmarks,
  structures, offsets, signatures, migration decisions, settings, and useful UI
  state. Native file-dialog/lifecycle interaction remains manually tested; a
  future schema version must add an explicit sequential migration in
  `MigrateProjectDocument`.
- C/C++ offset export is available through the clipboard. JSON supports both
  clipboard and file export/import; a C/C++ header importer is not implemented.

## State and architecture

- `Application` remains a broad composition root. `AnalysisSession` now owns the
  canonical database and project state; target buffers, scheduler jobs,
  navigation, and most panel orchestration still live on `Application`.
- `AnalysisTargetKind` is explicit, but legacy panel availability checks still
  use `isAttached` to mean "a target is open".
- `AnalysisDatabase` is canonical, while `AnalysisPanel`, `stringResults`, and
  `XRefScanner` retain compatibility display snapshots. CLI function lookup
  still reaches through the panel for some commands.
- Database indexes cover functions, Xrefs, strings, and globals. Structure-field
  stable IDs and signature-target indexes can be added when query consumers
  require them.
- Extension ABI v1 intentionally exposes only target and function snapshots.
  Bounded read-only CFG, Xref, string, global, structure, offset, signature, and
  Version Intelligence views require additive ABI design as real consumers
  emerge.
- Native extensions are trusted in-process code and are not sandboxed. A future
  out-of-process host, RPC contract, operating-system restrictions, and signed
  distribution require separate threat modeling and research.
- The WorkOS native public-client flow is implemented, but a legitimate
  provider application/client configuration and live end-to-end verification
  are still required before Phase E can be marked complete. If future provider
  requirements demand confidential operations, those operations belong behind
  the separate Phase F backend rather than in the desktop or website.
- Account access-token refresh is explicit through the account UI. Automatic
  refresh scheduling and expiry-driven retry policy should be added only after
  the production provider flow is verified.

## Performance

- A single scheduler worker avoids publication races but serializes independent
  jobs. Keep this until target ownership is fully isolated.
- Version Intelligence indexes reduce expensive candidate scoring, but signature
  migration still scans patterns independently and copies the new target
  snapshot into its background job. Profile large binaries before introducing
  shared immutable buffers or a multi-pattern matcher.
- Executable bytes are decoded for candidate extraction and again for bounded
  per-function CFGs. Add a decoded-instruction cache only after profiling shows
  material benefit.
- Signature uniqueness scans each generated pattern independently. A multi-
  pattern index would help large modules but needs measurement first.
- Phase durations are recorded/logged, but no persisted benchmark baseline or
  profiler UI exists.

## UI and testing

- The CFG panel presents typed blocks and edges rather than a spatial graph.
- Several ImGui tables advertise sorting without consuming sort specifications.
- Core tests cover the deterministic models and loaders. Application lifecycle,
  native dialogs, minidump UI selection, and installer UI do not have automated
  interaction tests.
- Extension manifest, ABI compatibility, project state, command, panel, and
  callback failures are covered at the host layer. Desktop menu/docking behavior
  remains manually tested.
- Authentication primitives, callback rejection, state lifecycle, rotation,
  logout, loopback binding, and isolated secure storage are automated. Browser
  launch, real provider consent, and live provider logout remain manual tests.

## Build and packaging

- Recursive CMake source globbing makes application source additions implicit.
- A clean configure downloads pinned dependencies unless already cached.
- The combined GUI/CLI executable uses the Windows GUI subsystem, so PowerShell
  automation must wait explicitly for reliable exit codes.
- WinGet metadata remains intentionally absent until a matching checksummed
  GitHub release is published.
