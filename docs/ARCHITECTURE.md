# OpenReverse architecture

Last updated: 2026-08-12

## Composition

OpenReverse is a Windows C++17 application using Win32, DirectX 11, Dear ImGui,
Capstone, WinHTTP, DbgHelp, BCrypt, and nlohmann/json. `Application` remains the
composition root for target lifecycle, analysis services, the scheduler, the
canonical database, navigation, and panels.

## Targets and address spaces

`AnalysisTargetKind` distinguishes disk PE files, mapped dumps, raw dumps,
captured minidump modules, and live processes. Analysis code uses explicit
address-space behavior:

- `PEFileAddressSpace` translates RVA through section raw offsets.
- `MappedImageAddressSpace` maps RVA directly into an RVA-shaped byte buffer.
- `DumpAddressSpace` applies the user-supplied or captured image base.
- `ProcessAddressSpace` represents live virtual addresses.

Raw PE files are validated and mapped before VA-oriented analysis. Section
virtual tails beyond `SizeOfRawData` are zero-filled. An already mapped image is
never translated through `PointerToRawData`.

`DumpLoader` never executes input. It accepts a complete mapped PE image, a raw
snapshot with explicit architecture/base/size, or a Windows minidump module
whose captured ranges include usable mapped PE headers. Multi-module minidumps
require an explicit module selection.

## Shared analysis pipeline

`ModuleAnalyzer` owns the common live and mapped-image pipelines. The pipeline
validates PE metadata, decodes bounded executable ranges, discovers functions,
builds CFGs and operand-level Xrefs, scans strings, derives globals and field
evidence, builds typed offsets, and generates bounded candidate signatures.

x64 function discovery prioritizes validated `RUNTIME_FUNCTION` entries,
followed by symbols when a provider is available, exports, entry point, decoded
direct calls, recursive traversal, and finally prologue heuristics. A
`FunctionInfo` keeps authoritative boundaries separate from its bounded analyzed
extent.

The result is immutable on the worker. A scheduler completion callback publishes
it on the UI thread only when the captured target generation is still active.
Opening a PE or dump from the desktop uses this scheduled path; CLI analysis may
run it synchronously because no ImGui loop is present.

## Deterministic models

Capstone details are retained per instruction: register/immediate/memory
operands, base/index/scale/signed displacement, width, read/write access,
register access, groups, encoding offsets, and resolved RIP-relative targets.
`XRefEntry` records every meaningful resolved operand with its index, width,
source function, and typed access.

Global candidates retain VA, RVA, section, access counts, source instructions,
source functions, operand widths, and all contributing Xrefs. Field evidence
retains base/index/scale/displacement/width/access and basic register origin.
Block-local propagation follows straightforward `MOV` and `LEA` relationships,
seeds RCX/RDX/R8/R9 as Windows x64 arguments 1–4, rejects stack locals, and stops
when a transform is ambiguous.

Structure candidates group compatible fields by containing function and root
argument/register evidence. They are explicitly inferred candidates, not
recovered source types. `EvidenceLevel` and raw `evidenceScore` communicate the
kind and amount of evidence without claiming calibrated probability.

## Signatures, offsets, and comparison

`OffsetRecord` distinguishes global, structure-field, function, import, export,
pattern, and user-defined locations and retains provenance. `ModuleIdentity`
uses SHA-256 plus PE timestamp, image size/base, and optional version/PDB fields.
nlohmann/json performs bounded project import/export; imported data is parsed as
data and never executed.

Signatures use a byte-plus-wildcard model, so literal `FF` bytes remain literal.
Generation wildcards relative branch/call immediates, RIP displacements,
in-module absolute pointers, and supplied relocation RVAs. Relationships resolve
a match to a function RVA, RIP-relative global, or field displacement. Scans
report unique, ambiguous, not-found, or invalid; migration never auto-accepts an
ambiguous match.

Function fingerprints normalize instruction IDs and operand classes and combine
them with CFG shape, referenced strings, call count, and instruction count.
Comparison returns a transparent similarity score and evidence list, not a
probability.

`ISymbolProvider` defines optional symbol/type ingestion. No concrete DIA/PDB
provider is shipped yet, so symbols are not required for analysis.

## Canonical state and indexes

`AnalysisDatabase` is the canonical per-module store for PE data, functions,
CFGs, Xrefs, strings, globals, fields, structures, offsets, signatures, and
module identity. It rebuilds deterministic indexes for function addresses,
source/target Xrefs, strings, and globals whenever a module snapshot changes.
User-defined offsets survive automatic replacement. Some panels retain display
snapshots, but they do not run separate analysis pipelines.

## Lifecycle and safety

Detach and shutdown cancel jobs, wait for the worker, clear database and panel
state, advance the generation, release offline buffers, then close the live
process handle. Windows access denial is reported factually with disk, dump, and
saved-project alternatives; OpenReverse does not attempt protection bypasses.

## Verification

The Release regression path is:

```powershell
cmake --build --preset windows-x64-release --parallel
ctest --test-dir build/windows-x64 -C Release --output-on-failure
```

`OpenReverse.Core` covers raw/mapped addressing, `.pdata`, mapped dump loading,
operand Xrefs, globals, field provenance, register propagation, signatures,
function comparison, migration ambiguity, JSON, SHA-256 identity, database
indexes, scheduler publication/cancellation, and denied-access messaging.
