# Changelog

Notable user-visible changes will be recorded here. The repository does not yet
publish versioned GitHub releases, so earlier development history is not
reconstructed as release notes.

## Unreleased

### Changed

- Added distinct raw-file, mapped-image, dump, and process address spaces.
- Added static mapped-image, raw snapshot, and captured minidump-module analysis.
- Added x64 runtime-function boundaries, function provenance, operand-level
  Xrefs, global/field provenance, and simple Windows x64 register-origin flow.
- Added typed offset records, SHA-256 module identity, JSON/C++ export, decoded
  signatures, conservative migration results, and function fingerprinting.
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
