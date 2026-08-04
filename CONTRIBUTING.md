# Contributing

## Development setup

1. Install Visual Studio 2022 with the Desktop development with C++ workload.
2. Install CMake 3.23 or later and Git.
3. Configure the project with the `windows-x64` preset.

```powershell
cmake --preset windows-x64
cmake --build --preset windows-x64-release --parallel
```

## Change guidelines

- Keep changes focused on one concern.
- Preserve the existing C++17 and Windows x64 support matrix.
- Do not commit build directories, binaries, reports, credentials, or local configuration.
- Add or update a fixture under `tests/fixtures` when changing binary analysis behavior.
- Use clear names and explain non-obvious platform-specific code briefly.

## Pull requests

Describe the behavior changed, the validation performed, and any Windows-specific
requirements. Include screenshots for UI changes and a reproducible sample for
analysis changes when possible.
