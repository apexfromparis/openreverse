# OpenReverse Architecture Audit

> Historical baseline audit. For the current post-P0 design, see
> `docs/ARCHITECTURE.md`; for remaining work, see `docs/TECHNICAL_DEBT.md`.

Audit date: 2026-08-09

## Scope and baseline

This audit covers the first-party C++ sources, CMake configuration, installer,
scripts, documentation, test fixture, ImGui panels, analysis engines, and AI
client. Generated dependency sources under `build/windows-x64/_deps` are not
part of the product audit.

The repository is an exported working tree without `.git` metadata. Existing
files cannot therefore be attributed or compared through Git in this copy.

The untouched baseline was verified with:

```powershell
cmake --preset windows-x64
cmake --build --preset windows-x64-release --parallel
ctest --test-dir build/windows-x64 -C Release --output-on-failure
```

Configuration and both Release targets succeeded. CTest reported `No tests
were found`.

## Current architecture

OpenReverse is a Windows-only C++17 application. `src/main.cpp` owns one
`Application` and selects headless, CLI, or Win32/DirectX 11/ImGui execution.
The GUI uses ImGui docking and renders panels from `Application::Render()`.

`Application` is the current composition root and shared state container. It
owns the process manager, memory reader, PE parser, Capstone wrapper, function
analyzer, Xref scanner, string and pattern scanners, AI service, and all UI
panels. Panels receive `Application&` and communicate by directly invoking
these engines or updating shared target and selection state.

The main data flows are:

- Live target: `ProcessManager` opens a process, `MemoryReader` reads it,
  `ModuleManager` enumerates modules, and analyzers consume copied buffers.
- Offline target: `PEParser::ParseFile` retains the raw PE file, builds a
  section-aware RVA image, and exposes that mapped image through `MemoryReader`
  as a synthetic module.
- Disassembly: `Disassembler` wraps Capstone 5 in x86/x64 detail mode.
- Functions: `FunctionAnalyzer` combines prologue heuristics, call targets, PE
  entry/export seeds, linear instruction analysis, and basic-block summaries.
- Xrefs: `XRefScanner` disassembles a buffer, indexes references by source and
  target, and serves exact or text queries to UI and automation paths.
- AI: `AIService` runs blocking WinHTTP requests on one worker thread, uses an
  OpenAI-compatible chat schema, and stores API keys in Windows Credential
  Manager. `Application` assembles selected analysis context.
- Persistence: ImGui persists layout; the editor reads and writes its workspace;
  bookmarks, offsets, analysis, and AI settings are otherwise memory-only.

The architecture is tightly coupled but understandable. A rewrite is not
justified. The immediate correctness issues can be addressed by strengthening
the existing parser and models and progressively narrowing direct shared-state
access.

## Current implemented features

- Windows process enumeration, attach/detach, architecture detection, and live
  memory reads.
- Live module enumeration and basic export inspection.
- Offline PE32 and PE32+ file opening with DOS, NT, optional-header, section,
  import, and export extraction for conventional files.
- Capstone-backed x86/x64 disassembly with Intel and AT&T syntax selection.
- Hex view, disassembly view, data inspector, process list, memory map, module
  list, PE view, strings, pattern scanner, bookmarks, offsets, console, and AI
  panels in an ImGui docking workspace.
- ASCII and limited UTF-16LE string scanning.
- AOB pattern parsing, wildcards, and live process-region scanning.
- Heuristic function discovery, function list, basic-block summaries, and
  cyclomatic-complexity estimates.
- Indexed call, jump, and data Xref queries.
- Module-relative offset capture and clipboard export.
- An OpenAI-compatible HTTP AI client, optional local endpoints, asynchronous
  requests, conversation state, and Credential Manager key storage.
- Headless process reports and a substantial CLI command implementation.
- A Win32 self-extracting installer target.

## Current partial features

- Offline PE analysis now uses checked raw/RVA conversion and a mapped image;
  some live-only panels and commands still need explicit offline paths.
- Function discovery has useful prologue and PE seed heuristics, but call
  discovery scans raw `0xE8` bytes instead of decoded instructions.
- Basic blocks and CFG metadata exist, but analysis is linear rather than a
  recursive reachability worklist and the UI is a block list rather than a
  visual graph.
- Xref storage and lookup are reusable, but reference extraction treats many
  immediate constants as addresses and guesses memory read/write access.
- Pattern scanning supports wildcards but has weak token validation and range
  edge cases; offline panel integration is absent.
- Unicode string scanning recognizes only printable ASCII encoded as UTF-16LE
  and does not preserve strings across chunks.
- The PE viewer and several scan panels assume a live process even when an
  offline target is selected.
- The offset panel stores module-relative addresses but has no operand-derived
  structure analysis, persistence, or safe JSON escaping.
- AI requests are functional for OpenAI-compatible APIs, but provider-specific
  protocols, model discovery, context levels, context preview, and persistent
  provider settings are absent.
- The integrated editor performs real file operations, but execution and
  plugin integration are not implemented.
- CLI implementation exists, but packaged CLI mode selection and several
  offline commands are incorrect.

## Current mock features

- Cloud account authentication, OAuth, subscription tiers, quotas, server
  location/latency, billing-cycle data, and compliance status.
- Plugin marketplace publishing, signature generation, royalties, sandbox
  shields, anti-debug patching, and anti-VM spoofing claims.
- Script execution buttons that only log success or apply a fixed built-in
  rename heuristic.
- Project/session labels that do not persist or restore analysis state.
- Pseudocode branding that describes a heuristic C-like assembly rendering as
  an industrial decompiler or third-party technology.

These surfaces must be removed, disabled, or explicitly marked development-only
until a real backend exists.

## Current bugs

### Critical

- Fixed in initial P0: offline VA reads now use an RVA-mapped image rather than
  treating RVAs as raw offsets.
- Fixed in initial P0: offline function, Xref, and string addresses are based on
  mapped executable/data sections.
- Fixed in initial P0: offline PE structures, ranges, counts, and strings are
  bounded and malformed fixtures fail closed.
- Fixed in initial P0: function call targets come from decoded Capstone
  instructions rather than bytewise `0xE8` scanning.
- Fixed in initial P0: ordinary immediate constants are excluded from Xrefs and
  RIP-relative memory accesses carry read/write/address-generation types.
- Fixed in initial P0: CLI function buffers use the selected address as their
  actual buffer origin.

### High

- Live and offline target state are both represented by `isAttached`; multiple
  panels call live Win32 APIs with a null process handle in offline mode.
- Function boundaries continue linearly after returns and unconditional jumps;
  the last return in a large scan window can absorb adjacent functions.
- Module-wide disassembly starts in PE headers/data and may stop before `.text`.
- Most expensive analysis executes synchronously from ImGui event handlers.
- The CLI filename predicate makes normal `OpenReverse.exe` launch the GUI even
  when the documented CLI path is used.
- The installer resource hardcodes `bin/Release/OpenReverse.exe`, breaking other
  configurations and single-config generators.
- Uninstall paths leave the installed executable behind.

### Medium

- `ModuleManager` can iterate beyond its fixed 1024-entry module array.
- Process attach always requests write and VM-operation rights despite read-only
  analysis being the normal operation.
- Pattern scan stepping can underflow for a pattern larger than a read chunk.
- String and pattern scan ranges are not always clamped to the requested end.
- Xrefs can accumulate across repeated automated scans unless callers clear them.
- Several navigation paths update only one panel-local address.
- Editor create/rename paths are not constrained to the workspace and dirty tab
  contents can be lost when switching or closing tabs.
- AI CLI setup saves a key before switching provider, placing it under the wrong
  Credential Manager target.

## Technical debt

- `Application` is a public mutable service locator. It should be narrowed only
  as shared analysis models stabilize; replacing it wholesale would create risk
  without fixing current correctness bugs.
- GUI, CLI, headless, and automation paths duplicate orchestration and sometimes
  pass different address semantics.
- Target-kind and address-space semantics are implicit. A small interface may be
  useful later, but a section-aware mapped offline image is sufficient for P0.
- Analysis results are split between panel-local containers and `Application`.
- Source collection uses recursive CMake globbing, dependency acquisition depends
  on network/Git, and ImGui tracks the mutable `docking` branch.
- Project version, installer version, and package metadata disagree.

## Security issues

- Input PE headers, section tables, import/export counts, strings, and arithmetic
  are not comprehensively bounded.
- Arbitrary remote plaintext HTTP AI endpoints are accepted and may receive API
  keys and selected target context.
- AI context is sent without a per-request preview and target-controlled strings
  are inserted into the system context.
- Editor path traversal can create or rename files outside its workspace.
- Live export tables can request large allocations from target-controlled counts.
- Logger readers race with background writes because an unlocked reference is
  returned.
- Plugin/script sandbox claims are especially unsafe because no sandbox exists.

## Performance issues

- Function, Xref, string, pattern, and PE analysis can block the GUI thread.
- Full multi-megabyte buffers are repeatedly copied and rescanned.
- Capstone can materialize every instruction and detail object for an entire
  module in one call.
- Export name lookup is quadratic.
- Pattern matching is naive and panel scans do not expose usable cancellation
  while the UI thread is blocked.

## UI/UX issues

- Unsupported cloud/account and marketplace surfaces are prominent.
- Third-party product names imply integrations that do not exist.
- Offline target selection leaves several live-only panels enabled but empty.
- Saved docking layouts are overwritten by the default layout on startup.
- Many advertised shortcuts and sortable table headers have no implementation.
- Xref shortcuts can focus the panel without populating the requested query.
- There is no application start screen or recent-project flow.
- Expensive actions lack progress, cancellation, and useful failure states.

## Test coverage

The baseline had no first-party automated tests. Initial P0 adds the
`OpenReverse.Core` CTest target and Windows CI. It covers synthetic and built PE
files, malformed headers and sections, raw/RVA mapping, mapped VA reads, named,
ordinal and forwarded exports, decoded calls, RIP-relative Xrefs, and pattern
validation. The crackme fixture remains manual and broader application/UI tests
are still absent.

Highest-value initial tests are PE32/PE32+ structure validation, RVA/raw mapping,
mapped-image reads, decoded-call discovery, RIP-relative references, malformed
patterns, CFG reachability, and serialization.

## Keep

- CMake, C++17, ImGui docking, DirectX 11, Capstone, nlohmann/json, WinHTTP, and
  Windows Credential Manager.
- Existing manager/analyzer classes and panel composition while their contracts
  are corrected.
- Existing PE metadata structures, prologue hints, Xref indexes, scanners,
  function/basic-block models, editor, AI conversation flow, and direct binary
  opening.

## Improve

- Make PE parsing fail closed and centralize checked RVA/raw conversion.
- Feed offline analysis a mapped image while retaining the original raw file.
- Decode executable sections before accepting direct call targets.
- Add operand/access metadata to shared instructions and Xrefs.
- Replace linear CFG boundaries progressively with recursive traversal.
- Move long-running analysis behind cancellable jobs after correctness is stable.
- Add explicit target kind and shared analysis result ownership incrementally.
- Require HTTPS except for exact loopback AI hosts and add context controls.

## Refactor

- Refactor only duplicated address calculations and target-state checks needed by
  a concrete fix.
- Preserve historical internal class names such as `IDAProPanel` and
  `OffsetsPanel` temporarily while changing user-visible terminology.
- Introduce provider, symbol, project, and plugin interfaces only when their
  second implementation or persistence boundary is being added.

## Remove

- Fake account, OAuth, subscription, quota, compliance, cloud-latency, plugin
  marketplace, sandbox, signing, and protection claims.
- IDA and Hex-Rays naming that implies integration or equivalent output.
- CLI/package claims for commands that are unreachable or simulated until fixed.

## Add

- Automated core tests and Windows CI.
- Checked raw/RVA/VA conversion and mapped-image construction.
- Executable-section analysis and decoded direct-call discovery.
- Shared typed Xrefs, RIP-relative globals, recursive CFG, structures, signature
  generation, projects, symbol providers, and AI context controls in the stated
  priority order.

## P0 implementation checklist

- [x] Inventory source, architecture, build, tests, UI, analysis, and AI.
- [x] Configure and build the untouched Release application and installer.
- [x] Run the untouched test entry point and record that no tests exist.
- [x] Add strict offline PE header/section/import/export bounds validation.
- [x] Add tested RVA-to-raw conversion and mapped-image construction.
- [x] Route offline memory, disassembly, strings, and function scans through the
  mapped image and executable sections.
- [x] Replace bytewise `0xE8` discovery with decoded direct-call targets.
- [x] Stop Xrefs from treating arbitrary immediates as addresses.
- [x] Fix the CLI function buffer-origin bug.
- [x] Remove misleading cloud/compliance/marketplace and third-party branding.
- [x] Add CTest coverage for changed core behavior.
- [x] Rebuild both Release targets and run all tests.

## Planned sequence after P0

P1 should consolidate typed Xrefs and shared analysis data, improve strings,
detect RIP-relative globals, and use recursive function discovery. P2 should
build a real CFG model and then structures, signatures, projects, and symbols.
AI provider abstraction and OpenRouter should follow reliable structured
analysis. Plugins and binary diff should wait for stable, versioned core models.
