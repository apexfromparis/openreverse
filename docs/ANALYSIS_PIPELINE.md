# Analysis pipeline

OpenReverse analyzes either a live process module or an offline PE image. Both
paths publish the same immutable module snapshots to `AnalysisDatabase`.

## Target preparation

For a live target, `ProcessManager` opens a read-only handle and
`ModuleManager` enumerates loaded modules. `MemoryReader` performs bounded
reads from committed, readable regions.

For an offline target, `PEParser` validates the raw file and maps headers and
sections by RVA. Virtual tails beyond `SizeOfRawData` are zero-filled so the
analysis address model matches a loaded image.

## Module analysis

`ModuleAnalyzer` performs bounded phases:

1. Parse PE metadata inside the module bounds.
2. Read readable blocks from executable sections.
3. Decode instructions and collect candidate functions and typed Xrefs.
4. Add entry point, export, call-target, and branch-target seeds.
5. Build bounded recursive control-flow graphs for candidate functions.
6. Scan readable sections for strings and pattern candidates.
7. Infer conservative non-code globals and object-relative fields/structures.

Function boundaries, indirect targets, generated summaries, and inferred data
types remain heuristic.

## Scheduling and publication

Live analysis runs through `AnalysisScheduler` on one worker thread. Jobs use a
cooperative cancellation token and return a completion callback. The
application executes completion callbacks on the UI thread, discarding results
whose target generation no longer matches the active target.

Detach and shutdown cancel and join analysis before target memory and panel
state are cleared. This prevents stale work from publishing into a new session.

## Consumers

The disassembly, CFG, Xref, strings, structures, and AI panels read the shared
analysis snapshot. Some panels still maintain compatibility views while the
database migration is completed; they must not introduce independent analysis
pipelines.
