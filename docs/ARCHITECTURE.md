# OpenReverse architecture

Last updated: 2026-08-18

## Composition

OpenReverse is a Windows C++17 application using Win32, DirectX 11, Dear ImGui,
Capstone, WinHTTP, DbgHelp, BCrypt, and nlohmann/json. The first-party source
tree follows the product's ownership boundaries:

- `src/analysis` contains PE parsing, disassembly, function and data evidence,
  signatures, diffs, and the bounded module-analysis pipeline.
- `src/targets` contains address spaces, dump loading, memory reads, process
  access, and the current module catalog.
- `src/workspace` owns canonical analysis state, scheduling, session state, and
  `.orev` persistence.
- `src/app` composes those domains and coordinates desktop/CLI lifecycles.
- `src/auth`, `src/extensions`, and `src/ai` are controlled subsystem
  boundaries; `src/ui` and `src/cli` are presentation and interaction layers.

`Application` remains the composition root for target lifecycle, analysis,
navigation, and panels. `AnalysisSession` owns the canonical `AnalysisDatabase`
plus persistent project/user state; `Application` keeps a compatibility
reference while orchestration moves incrementally to the session.

## Persistent projects

`ProjectStore` owns the versioned `.orev` data boundary. It performs bounded
typed decoding, canonical SHA-256 integrity checks, explicit version/migration
handling, target identity verification, and flushed temporary-file replacement.
Projects reference rather than embed binaries. Target-bound state is restored
only after the external target SHA-256 matches; a user-selected changed target
starts without annotations and requires Save As.

Function annotations and bookmarks use RVAs so they rebase with the verified
module. The session merges stored user offsets and signatures into a newly
computed deterministic analysis snapshot instead of trusting persisted results
as executable behavior. See [Project format](PROJECT_FORMAT.md).

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

`ModuleAnalysisPipeline` owns the common live and mapped-image pipeline. It
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
Propagation follows straightforward `MOV`, `LEA`, copies, and deterministic
spill/reload relationships, seeds RCX/RDX/R8/R9 as Windows x64 arguments 1–4,
and merges predecessor states across the CFG. Conflicting incoming origins are
marked ambiguous instead of choosing one. Bounded direct-call return evidence
is retained without claiming general interprocedural or alias analysis.

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
them with CFG topology, edge distribution, strings, imports, global roles,
stable signatures, field provenance, runtime boundaries, calls, and instruction
counts. Address-like immediates, relative branches/calls, and RIP-relative
displacements are normalized without discarding small semantic constants or
separate field evidence. Comparison returns a transparent heuristic score and
machine-readable evidence, not a probability.

`VersionIntelligenceEngine` builds normalized/CFG/data/signature indexes before
scoring plausible candidates. Exact and strong results may refine callers via
matched callees; weak candidates never reinforce each other. It produces
explicit removed/new/ambiguous states, deterministic function change summaries,
and conservative global, signature, typed-offset, and structure-field migration
records. See [Version Intelligence](VERSION_INTELLIGENCE.md).

The desktop comparison is submitted through `AnalysisScheduler`. The worker
loads and analyzes the old PE, compares immutable old/new snapshots, checks
cancellation, and publishes only when the current target generation still
matches. User decisions live in `AnalysisSession` and the additive version-1
project section.

`ISymbolProvider` defines optional symbol/type ingestion. The Windows DIA
provider validates PE CodeView GUID/age association and imports public/function
symbols, boundaries, structure fields, and enums when a compatible DIA runtime
and PDB are available. Symbol provenance remains distinct from heuristic facts;
analysis works normally without DIA or PDB files.

## Canonical state and indexes

`AnalysisDatabase` is the canonical per-module store for PE data, functions,
CFGs, Xrefs, strings, globals, fields, structures, offsets, signatures, and
module identity. It rebuilds deterministic indexes for function addresses,
source/target Xrefs, strings, and globals whenever a module snapshot changes.
User-defined offsets survive automatic replacement. `AnalysisPanel` and CLI
query this database rather than owning alternate function collections. A small
number of panels still consume compatibility Xref/string mirrors populated only
from the canonical published result; they do not run separate pipelines.

The build reflects these dependency boundaries with explicit reusable
`OpenReverseCore`, `OpenReverseAuth`, `OpenReverseExtensions`, and
`OpenReverseUI` libraries. Analysis and target code do not depend on Dear ImGui.
The CLI command implementation uses `Application` orchestration and canonical
session/database queries, never panel state. Extension hosting depends on the
versioned C ABI rather than UI internals; auth does not depend on the AI or UI
layers.

## Native extension boundary

`ExtensionManager` discovers manifest-backed DLLs only under the deliberate
application-local `extensions` root. It validates bounded manifests, semantic
and ABI compatibility, capabilities, duplicate IDs, canonical paths, the
exported descriptor, and initialization before publishing registrations. DLLs
load from explicit full paths with restricted Windows search flags.

The public Windows x64 C ABI in `sdk/include/openreverse/extension.h` exposes
fixed-layout function tables and caller-owned UTF-8 buffers. It deliberately
does not expose `Application`, `AnalysisSession`, `AnalysisDatabase`, STL types,
Dear ImGui, or borrowed collection pointers. V1 supplies read-only target and
function snapshots, controlled navigation, extension-owned project JSON state,
commands, and host-rendered text panels. See [Extensions](EXTENSIONS.md).

The application owns callback ordering and unloads extensions in reverse order
after shutdown callbacks. Native in-process extensions are trusted code, not a
sandbox boundary. Out-of-process isolation remains research.

## Optional account authentication

`src/auth` implements a separate native public-client account boundary. WorkOS
AuthKit Authorization Code + PKCE S256 uses an ephemeral `127.0.0.1` callback;
the pending verifier and random state live only for one bounded transaction.
The callback parser accepts a code and state, never final credentials.

`AuthSession` owns the account state machine, `IAccountApi` isolates provider
exchange/refresh/logout behavior, and `DesktopAuthClient` owns asynchronous
callback and network work. A short-lived access token stays in memory. A
refresh credential and bounded account metadata use Windows Credential Manager
under an account-specific target. AI BYOK storage remains a different
namespace, and account logout does not mutate projects or AI keys. See
[Desktop authentication](AUTHENTICATION.md).

Authentication is not an entitlement boundary and does not gate Community
features. Billing, licensing, subscriptions, hosted services, and authoritative
entitlements remain outside this Community repository.

## Lifecycle and safety

Detach and shutdown cancel jobs, wait for the worker, clear database and panel
state, advance the generation, release offline buffers, then close the live
process handle. Windows access denial is reported factually with disk, dump, and
saved-project alternatives; OpenReverse does not attempt protection bypasses.

## Verification

The Release and Debug regression paths are:

```powershell
cmake --build --preset windows-x64-release --parallel
ctest --preset windows-x64-release
cmake --build --preset windows-x64-debug --parallel
ctest --preset windows-x64-debug
```

`OpenReverse.Core` covers raw/mapped addressing, `.pdata`, mapped dump loading,
operand Xrefs, globals, field provenance, register propagation, signatures,
function comparison, migration ambiguity, JSON, SHA-256 identity, database
indexes, scheduler publication/cancellation, `.orev` round-trips, corruption,
atomic replacement, target mismatch/missing handling, session rebasing,
deterministic malformed-input mutations, and denied-access messaging.
Controlled Version Intelligence fixtures cover indexed
matching, ambiguity, false positives, deterministic changes, relationship-aware
migrations, cancellation, and persisted decisions.

`OpenReverse.Auth` runs without provider network access. It covers RFC 7636
vectors, cryptographic verifier/state properties, strict callback parsing,
credential-field injection, state mismatch, replay, timeout, cancellation,
exchange and refresh failures, logout, loopback binding, and isolated Windows
Credential Manager store/read/replace/delete behavior. `OpenReverse.StaticOpen`
protects the no-execution invariant, and `OpenReverse.CorpusValidation` checks a
valid Unicode-path PE and malformed candidate through the JSON corpus tool.
