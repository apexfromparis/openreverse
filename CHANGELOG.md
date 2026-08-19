# Changelog

Notable user-visible changes will be recorded here. The repository does not yet
publish versioned GitHub releases, so earlier development history is not
reconstructed as release notes.

## Unreleased

### Changed

- Hardened the deterministic analysis pipeline with Capstone metadata semantics,
  canonical per-function CFG publication, inter-block register-origin merging,
  optional DIA/PDB ground truth, and richer field provenance.
- Upgraded Version Intelligence matching with ordered instruction/block
  evidence, typed CFG neighborhoods, staged indexes, bounded candidate work,
  cached signature scans, and stronger ambiguity/scaling regressions.
- Added a navigable graphical CFG, Unicode/long-path Windows workflows,
  reusable CMake libraries, first-party `/W4`, Release/Debug CI, parser mutation
  coverage, and a static JSON corpus-validation tool.
- Removed the misleading legacy executable-launch analysis command and added
  execution-sentinel coverage for normal, Unicode, and corpus static opens.
- Added an optional native account foundation integrated with Supabase Auth
  and authoritative `GET /api/me` profile synchronization, supporting native
  email/password sign-in, session restore with refresh-token rotation,
  isolated Windows Credential Manager storage, explicit auth state machine,
  Settings > Account UI, and commercial fail-closed verification.
- Added a versioned Windows x64 native extension ABI, bounded manifests,
  controlled read-only analysis queries, commands, navigation, host-rendered
  panels, lifecycle diagnostics, extension-owned project state, compatibility
  fixtures, and a standalone Community SDK example.
- Added distinct raw-file, mapped-image, dump, and process address spaces.
- Added static mapped-image, raw snapshot, and captured minidump-module analysis.
- Added x64 runtime-function boundaries, function provenance, operand-level
  Xrefs, global/field provenance, and simple Windows x64 register-origin flow.
- Added typed offset records, SHA-256 module identity, JSON/C++ export, decoded
  signatures, conservative migration results, and function fingerprinting.
- Added an experimental Version Intelligence workspace with indexed normalized
  function matching, structured evidence, deterministic change summaries,
  explicit ambiguity, conservative typed migrations, background cancellation,
  and `.orev`-persisted review decisions.
- Moved desktop offline analysis onto the bounded scheduler and expanded the
  **Offsets & Structures** workspace with real deterministic data.
- Replaced fabricated C-like output with a decoded control-flow assembly summary.
- Unified application, CLI, Windows resources, and installer metadata around
  the CMake project version.
- Refined the docked workspace, navigation, disassembly, hex, structures, and
  optional AI presentation.
- Hardened bounded analysis, target teardown, state publication, and core
  regression coverage.
- Reorganized CLI, vendored editor, assets, build scripts, and public
  documentation.

### Fixed

- Raw PE offsets are no longer confused with RVA-mapped image offsets.
- Unknown function boundaries, sizes, and complexities are no longer displayed
  as deterministic values.
- Denied live-process access now reports safe offline alternatives without
  retrying or proposing protection bypasses.
- The installed uninstaller now removes the application binary, shortcuts, and
  uninstall registry entry instead of invoking the application as an
  uninstaller.
