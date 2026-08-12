<p align="center">
  <img src="assets/branding/openreverse-logo.png" alt="OpenReverse" width="220">
</p>

# OpenReverse

Open-source reverse-engineering workspace for Windows.

[![Windows CI](https://github.com/apexfromparis/openreverse/actions/workflows/windows-ci.yml/badge.svg)](https://github.com/apexfromparis/openreverse/actions/workflows/windows-ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

![OpenReverse workspace](assets/screenshots/workspace.png)

OpenReverse combines offline PE analysis and read-only live-process inspection
in a native C++17 desktop application. Its docked workspace keeps disassembly,
hex data, cross-references, structures, modules, and optional AI context visible
together.

## Features

### Available

- PE32/PE32+ parsing with section-aware offline image mapping
- Read-only Windows process attachment, memory maps, and module inspection
- x86/x64 disassembly powered by Capstone
- Heuristic function discovery and bounded recursive control-flow graphs
- Typed call, branch, RIP-relative data, and address cross-references
- ASCII and limited UTF-16 string scanning
- AOB pattern scanning with wildcard support
- Hex view, data inspector, bookmarks, and module-relative offsets
- Interactive command shell and optional OpenAI-compatible AI client
- User API-key storage through Windows Credential Manager

### Experimental

- C-like summaries generated from decoded instructions
- Heuristic function/Xref discovery and inferred globals, fields, and structures
- CFG block/edge presentation without a spatial graph layout
- AI explanations assembled from the current analysis selection
- Integrated script editor; script execution and a plugin API are not available

Experimental output is not authoritative. Confirm inferred code, control flow,
and types against the disassembly.

### Planned

Project persistence, symbol/PDB support, deeper data-flow analysis, binary
comparison, and a versioned extension API are tracked in the
[roadmap](ROADMAP.md). Planned work is not included in the current build.

## Installation

OpenReverse does not currently publish a GitHub release. Build it from source
using the commands below. Future installers will use the canonical name
`OpenReverse-x.y.z-Setup.exe`; release binaries belong in GitHub Releases, not
in this repository.

## Build from source

Requirements:

- Windows 10 or later
- Visual Studio 2022 with the **Desktop development with C++** workload
- CMake 3.23 or later
- Git, used by CMake to fetch pinned dependencies

```powershell
cmake --preset windows-x64
cmake --build --preset windows-x64-release --parallel
ctest --test-dir build/windows-x64 -C Release --output-on-failure
```

Outputs are written to `build/windows-x64/bin/Release/`:

- `OpenReverse.exe`
- `OpenReverse-2.0.0-Setup.exe`
- `OpenReverseCoreTests.exe`
- `OpenReverseTestFixture.exe`

See [Building](docs/BUILDING.md) for details.

## CLI

Launching without arguments starts the desktop workspace. Command-line entry
points use the same executable:

```powershell
build\windows-x64\bin\Release\OpenReverse.exe --help
build\windows-x64\bin\Release\OpenReverse.exe --version
build\windows-x64\bin\Release\OpenReverse.exe --cli
build\windows-x64\bin\Release\OpenReverse.exe open path\to\sample.exe
```

Because this is a Windows GUI-subsystem executable, automation should use
`Start-Process -Wait -PassThru` when it needs a reliable exit code.

## Architecture and AI privacy

The [architecture](docs/ARCHITECTURE.md) and
[analysis pipeline](docs/ANALYSIS_PIPELINE.md) documents describe target
ownership, scheduling, and analysis boundaries.

AI is optional. Selected context may include target names, disassembly,
strings, and generated summaries. Remote endpoints must use HTTPS; plaintext
HTTP is accepted only for exact loopback hosts. Review the provider's policy
before transmitting proprietary or sensitive data.

## Project information

- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

Use OpenReverse only on binaries and processes you own or are explicitly
authorized to inspect.

## Community

Use [GitHub Issues](https://github.com/apexfromparis/openreverse/issues) for
reproducible bugs and focused feature requests. Development discussion is also
available in the [OpenReverse Discord community](https://discord.gg/4mmhKcy6US).

## License

OpenReverse is distributed under the [MIT License](LICENSE).
