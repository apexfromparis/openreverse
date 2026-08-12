# Contributing to OpenReverse

## Set up a build

Install Visual Studio 2022 with Desktop development with C++, CMake 3.23 or
later, and Git. From the repository root:

```powershell
cmake --preset windows-x64
cmake --build --preset windows-x64-release --parallel
ctest --test-dir build/windows-x64 -C Release --output-on-failure
```

See [Building](docs/BUILDING.md) for output paths and smoke-test guidance.

## Changes

- Keep each change focused and preserve C++17 and Windows x64 support.
- Put analysis behavior in `src/core`, lifecycle coordination in `src/app`,
  CLI interaction in `src/cli`, and presentation in `src/ui`.
- Treat inferred functions, control flow, pseudocode, and types as heuristic.
- Add or update a small fixture/test when analysis behavior changes.
- Explain only non-obvious PE, Windows, concurrency, ownership, or security
  decisions in comments.
- Do not commit binaries, build trees, reports, credentials, or local settings.
- Avoid style-only changes in `src/ui/vendor` and generated resources.

## Issues and pull requests

Search existing issues first. Bug reports should include the OpenReverse and
Windows versions, reproduction steps, expected behavior, and sanitized logs or
screenshots. Never attach private binaries, credentials, or memory dumps.

Pull requests should explain what changed, why it changed, and the exact tests
performed. Include before/after screenshots for visible UI changes and a small
reproducible sample for analysis changes where possible.
