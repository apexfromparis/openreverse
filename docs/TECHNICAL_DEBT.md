# OpenReverse Technical Debt

Last updated: 2026-08-12

## High Priority

- Offline `OpenBinaryFile` analysis is still synchronous. Move its existing
  section-aware pipeline behind `AnalysisScheduler` without changing mapped PE
  address semantics.
- Live and offline targets still share `isAttached`. Introduce an explicit
  target-kind value when the remaining live-only panel checks are migrated.
- Panel-local function, Xref, and string vectors remain compatibility views of
  `AnalysisDatabase`. Continue migration when touching those panels; do not add
  another store.

## Analysis Accuracy

- Function discovery remains heuristic. Recursive CFG construction is bounded
  and correct for decoded seeds, but function boundaries and indirect targets
  are not recovered comprehensively.
- Field ownership uses the nearest discovered function and register/offset
  observations. It does not perform register provenance, alias, points-to, or
  interprocedural data-flow analysis.
- Structure candidates are per-function observations. Merging layouts across
  call sites requires evidence-based argument and object identity tracking.
- Globals intentionally exclude executable targets but do not yet distinguish
  imports, vtables, constants, and mutable variables as separate semantic kinds.
- UTF-16 and cross-block string recovery remain limited.

## Performance

- Module analysis decodes executable blocks for candidate extraction and also
  decodes reachable function instructions for CFG construction. Cache decoded
  instructions only if profiling shows this duplication dominates.
- One scheduler worker prevents analysis races but also serializes independent
  jobs. Keep this until result publication and target ownership are fully
  isolated.
- Database merge operations use linear vector searches. Replace them with
  internal indexes only when module-scale profiling justifies the complexity.
- Live phase timings are logged, but there is no historical profiler UI or
  persisted benchmark baseline.

## UI And Persistence

- The CFG panel presents typed navigable blocks and edges, not a spatial graph
  layout. A graph canvas needs deterministic layout, zoom/pan, and large-graph
  virtualization before being added.
- Inferred names, structures, bookmarks, offsets, and analysis snapshots are not
  persisted as a project.
- Several ImGui tables advertise sorting without applying sort specifications.
- Application/UI tests are absent; current automation exercises core models and
  analyzers only.

## Build And Packaging

- Recursive CMake source globbing makes source additions implicit.
- Dependency configuration still depends on fetched source trees on a clean
  machine.
- The shared GUI/CLI executable uses the Windows GUI subsystem. PowerShell
  automation must wait explicitly to obtain a reliable exit code.
- WinGet metadata was removed because no matching release exists. Recreate it
  from a published, checksummed installer if package distribution resumes.
