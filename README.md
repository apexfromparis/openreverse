# OpenReverse Studio

OpenReverse is an open-source reverse-engineering workspace for Windows,
written in C++, with optional AI integration.

The project is under active development. Interfaces and analysis results may
change between releases.

## Available

- PE32/PE32+ parsing and section-aware offline image mapping
- Windows process attachment, memory map, and module inspection
- x86/x64 Capstone disassembly
- Heuristic function discovery and recursive control-flow graphs
- Typed call, jump, RIP-relative read/write, and address Xrefs
- ASCII and limited UTF-16 string scanning
- AOB pattern scanning with wildcards
- Hex view, data inspector, bookmarks, and module-relative offsets
- ImGui docking workspace and interactive command shell
- Optional OpenAI-compatible AI client with Windows Credential Manager storage

## Experimental

- C-like pseudocode generated from decoded instructions
- CFG metadata and basic-block presentation
- Automated function and Xref discovery heuristics
- Memory-operand-derived global, field, and structure candidates
- AI context assembled from the selected target
- Integrated script editor; script execution and plugin APIs are not available

Experimental output is not authoritative. Validate inferred functions, types,
control flow, and pseudocode against the disassembly.

## Planned

- Data-flow analysis
- Signature generation and binary comparison
- Persistent `.orev` projects and symbols/PDB support
- Persistent provider settings and configurable context levels
- A versioned plugin API after core analysis models stabilize

Planned features are not included in the current build.

## Repository layout

- `src/`: application and analysis source code
- `installer/`: Windows installer source and resources
- `tests/fixtures/crackme/`: small local analysis fixture
- `scripts/`: build and installation helpers
- `assets/`: project branding and static assets

Build directories, binaries, reports, and local provider settings are ignored
by Git and should not be committed.

## Requirements

- Windows 10 or later
- Visual Studio 2022 with C++ desktop tools
- CMake 3.23 or later
- Git for CMake FetchContent dependencies

## Build

```powershell
cmake -B build -A x64
cmake --build build --config Release --parallel
```

Or use the checked-in Windows preset:

```powershell
cmake --preset windows-x64
cmake --build --preset windows-x64-release --parallel
```

The build produces the `OpenReverse` and installer targets. Use only
on binaries and processes you are authorized to inspect.

## Tests

```powershell
ctest --test-dir build/windows-x64 -C Release --output-on-failure
```

Core tests cover PE validation and mapping, recursive CFGs, typed Xrefs, offline
patterns, scheduler cancellation, shared analysis state, and inferred data
candidates.

## CLI

```powershell
.\build\bin\Release\OpenReverse.exe --help
.\build\bin\Release\OpenReverse.exe --cli
```

With the preset build, use `build\windows-x64\bin\Release\OpenReverse.exe`.
Launching without `--cli` starts the GUI. The shell supports opening PE files,
attaching to processes, disassembly, function analysis, strings, Xrefs, reports,
and optional AI-assisted queries.

The GUI and command shell share a Windows GUI-subsystem executable. PowerShell
scripts that require a reliable exit code should launch it with
`Start-Process -Wait -PassThru`.

## AI privacy

AI is optional. API keys are user-supplied and stored in Windows Credential
Manager. Remote endpoints must use HTTPS; plaintext HTTP is accepted only for
the exact loopback hosts `localhost`, `127.0.0.1`, and `::1`. Selected analysis
context may contain target names, disassembly, strings, and pseudocode. Review
provider policies before transmitting proprietary or sensitive data.

OpenReverse does not include a hosted account, subscription, marketplace, or
cloud compliance service in this repository.

## License

This project is distributed under the MIT License. See `LICENSE`.
