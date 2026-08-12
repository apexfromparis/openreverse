# Confirmed remaining analysis work

Verified against the implemented 2026-08-12 analysis pass. The canonical
product version remains `2.0.0` from the top-level CMake project.

## P0 Correctness

No release-blocking correctness issue is currently confirmed by the regression
suite. Malformed/sparse real-world dumps and PE edge cases should continue to be
reported with minimized fixtures when found.

## P1 Analysis quality

- `ISymbolProvider` has no DIA/PDB implementation, so symbol and type ground
  truth is not yet imported.
- register-origin propagation is block-local; predecessor merging, aliasing,
  interprocedural flow, indirect targets, and pointer chains remain unresolved.
- signature generation accepts relocation RVAs but the PE base-relocation
  directory is not yet fed into the shared pipeline.
- the minidump loader requires sufficiently complete captured module headers and
  ranges; sparse modules fail explicitly instead of attempting reconstruction.
- function fingerprinting exists as a core foundation, but the desktop Migration
  view currently evaluates imported signatures rather than a full old/new
  function-neighborhood comparison.

## P2 Architecture

- `AnalysisDatabase` is canonical, but remaining panel snapshots and several CLI
  function queries are compatibility consumers rather than direct database
  queries.
- `Application` still combines target session, navigation, and UI orchestration.
- structure/signature indexes are not present because current consumers iterate
  once per database revision; add them when query patterns justify them.

## P3 Product and UX

- persistent OpenReverse projects and an **Open Project** workflow do not exist.
- accepted migration candidates cannot yet be saved as user decisions.
- application/native-dialog/UI automation is absent; dump configuration and
  installer interaction are verified manually.
- the CFG view is navigable but has no deterministic spatial graph layout.
