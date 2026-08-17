# Analysis pipeline

OpenReverse publishes disk files, dumps, and authorized live modules into the
same `ModuleAnalysisResult` and `AnalysisDatabase` models.

## Target preparation

| Input | Address rule | Required metadata |
| --- | --- | --- |
| Raw PE file | RVA translates through section raw offsets | Valid PE headers |
| Mapped PE image | RVA is an index in the mapped image | Complete mapped headers |
| Raw snapshot | Dump offset maps from an explicit image base | x86/x64, base, module size |
| Minidump module | Captured VA ranges are copied into an RVA-shaped module image | Module selection when ambiguous |
| Live module | VA is read through bounded Windows APIs | Authorized read handle |

Critical dump metadata is never guessed. Static inputs are never launched or
loaded as executable modules.

## Bounded stages

1. Validate the target and PE metadata within the declared module bounds.
2. Parse imports, exports, and x64 exception-directory runtime functions.
3. Decode executable ranges while preserving detailed operand/access metadata.
4. Seed functions from runtime functions, symbols when available, exports, entry
   point, decoded calls, traversal evidence, and heuristics in that order.
5. Build bounded recursive CFGs and record known boundaries separately from
   analyzed extents.
6. Emit one typed Xref for each meaningful resolved operand and assign its
   containing function.
7. Scan bounded readable ranges for strings.
8. Derive RIP-relative globals and conservative inter-block object-field
   evidence, preserving ambiguity at conflicting CFG merges.
9. Group conservative structure candidates and build typed offsets.
10. Generate and uniqueness-test a bounded set of function signatures for
    mapped static inputs.
11. Publish the complete snapshot and rebuild query indexes.

Each stage observes byte, instruction, function, string, result-count, time, and
cancellation limits. Truncation and cancellation remain explicit in the result.
The result records disassembly/discovery, CFG, data/structure, string,
signature, and total durations. Progress values advance from completed work;
no timer-based progress is used.

## Evidence and uncertainty

Runtime-function ranges and valid PE metadata are `Known`. Resolved operands,
global locations, agreed predecessor register origins, and simple copies are
deterministic observations used to form `Inferred`, `Heuristic`, or `Partial`
candidates. `evidenceScore` is a raw
evidence count/weight, not a calibrated confidence percentage.

The assembly summary reproduces decoded instructions grouped by basic block. It
does not generate source parameters, source variables, conditions, return types,
or semantic names.

## Signatures and migration

Signature bytes are explicit literals or wildcards. Relative control-transfer
immediates, RIP-relative displacements, in-module absolute pointers, and supplied
relocations can be wildcarded. A relationship may resolve the match itself, a
function RVA, a RIP-relative global, or a field displacement.

Imported JSON is bounded and parsed with nlohmann/json. Migration scans imported
signatures once per import/database revision and reports `Unique`, `Ambiguous`,
`Not found`, or `Invalid`. Only unique valid results expose a candidate; no weak
or ambiguous candidate is silently accepted.

Function fingerprint comparison is a separate core foundation. It returns
ranked candidates with explicit similarity scores and contributing evidence.

## Local corpus validation

`OpenReverseValidation <directory> [--output report.json] [--max-files N]`
recursively processes common PE extensions through the same bounded mapped-image
pipeline. It never executes or dynamically loads candidates. The JSON report
uses paths relative to the supplied root and records raw-file SHA-256,
architecture, success/partial/failure/exception status, analysis counts, budget
flags, errors, and stage timings. Local reports are ignored by Git.

## Scheduling and publication

Desktop PE/dump analysis runs through `AnalysisScheduler`. Workers receive a
cooperative cancellation token and return a UI-thread completion callback.
Callbacks whose target generation no longer matches are discarded. CLI mode may
invoke the same module analyzer synchronously because it has no render loop.

Detach and shutdown cancel and join active analysis before target memory and
panel state are released.

## Consumers

The workspace, CLI, report generator, and optional AI context consume the shared
database result. AI output is always a suggestion layer and is never written
back as deterministic structure or offset evidence without an explicit future
acceptance workflow.
