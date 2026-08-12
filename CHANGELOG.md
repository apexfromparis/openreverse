# Changelog

Notable user-visible changes will be recorded here. The repository does not yet
publish versioned GitHub releases, so earlier development history is not
reconstructed as release notes.

## Unreleased

### Changed

- Unified application, CLI, Windows resources, and installer metadata around
  the CMake project version.
- Refined the docked workspace, navigation, disassembly, hex, structures, and
  optional AI presentation.
- Hardened bounded analysis, target teardown, state publication, and core
  regression coverage.
- Reorganized CLI, vendored editor, assets, build scripts, and public
  documentation.

### Fixed

- The installed uninstaller now removes the application binary, shortcuts, and
  uninstall registry entry instead of invoking the application as an
  uninstaller.
