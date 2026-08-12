# OpenReverse Architecture

Last updated: 2026-08-12

## Composition

OpenReverse is a Windows C++17 application using Win32, DirectX 11, ImGui,
Capstone, WinHTTP, and nlohmann/json. `Application` is the composition root. It
owns target services, analysis engines, the scheduler, the analysis database,
and UI panels.

## Target Model

Live targets use a read-only process handle, enumerated `ModuleInfo` records, and
bounded `ReadProcessMemory` reads. Offline PE targets retain both raw file bytes
and an RVA-mapped image. `MemoryReader` exposes the mapped image through the same
VA-oriented read interface used by panels.

Target teardown follows this order:

1. Cancel analysis jobs and wait for the worker.
2. Clear database, panel, Xref, string, and AI conversation state.
3. Advance the target generation used by panel caches.
4. Close the process handle and clear mapped offline buffers.

This order prevents worker completion callbacks from publishing into a detached
target.

## Analysis Pipeline

`ModuleAnalyzer` is the shared live module pipeline used by the GUI and
`Automator`. It performs these bounded phases:

1. Parse PE metadata within the mapped module size.
2. Read committed, readable blocks from executable sections.
3. Decode instructions, discover functions, build typed Xrefs, and collect
   object-relative field accesses.
4. Add PE entry/export and decoded-call function seeds.
5. Read bounded readable sections for strings.
6. Infer non-code globals and conservative per-function structure layouts.

The result is immutable while on the worker and is published only by the
scheduler completion callback on the UI thread. Code bytes, decoded instruction
counts, string bytes, function counts, duration budgets, cancellation, and phase
durations are bounded or recorded in `ModuleAnalysisResult`.

Offline opening uses the same decoders and candidate analyzers over mapped PE
sections. It publishes the same database models but remains synchronous.

## Scheduler

`AnalysisScheduler` owns one worker thread. Jobs receive a cooperative
`CancellationToken` and progress callback. Workers return completion functions;
`Application::Render` drains those functions on the UI thread. Process detach
and application shutdown cancel and join jobs before releasing target state.
Completed work closures release captured resources, and job history is bounded.

## Shared State

`AnalysisDatabase` is the canonical module-analysis store. A module snapshot
contains:

- PE and architecture metadata
- functions and recursive control-flow graphs
- typed Xrefs and strings
- inferred global candidates
- object-relative field accesses and inferred structures
- a monotonic revision

Complete analysis replaces a module snapshot so stale automatic records are
removed. Later analysis stages can use the incremental merge API, which updates
records by stable address/type keys. Existing panel-local vectors remain
compatibility views while panels are migrated; they are not independent
analysis pipelines.

## CFG Model

`FunctionAnalyzer::AnalyzeFunction` uses a bounded recursive worklist. A
`ControlFlowGraph` owns basic blocks and typed edges: fallthrough, conditional
true, conditional false, unconditional, and return. Blocks expose predecessor
and successor addresses. Invalid or external targets are represented without
being decoded, and instruction-budget truncation is explicit.

## Data Inference

Global candidates are typed Read, Write, ReadWrite, or Lea Xref targets in mapped,
non-executable PE sections. Counts, access sites, section names, module offsets,
and confidence are retained.

Field candidates come from non-indexed Capstone memory operands with a non-stack
base register and a small non-negative displacement. They retain operand width,
access type, instruction address, and inferred owning function. Structure
candidates group at least two distinct offsets observed with the same base
register in one function. These are candidates, not recovered source types.

## Verification

The Release regression path is:

```powershell
cmake --build --preset windows-x64-release --parallel
ctest --test-dir build/windows-x64 -C Release --output-on-failure
```

`OpenReverse.Core` covers PE validation/mapping, bounded live reads, decoded
calls, recursive CFG behavior, typed Xrefs, offline patterns, scheduler
publication/cancellation, database replacement/merge behavior, and global,
field, and structure candidate inference.
