# OpenReverse Studio

OpenReverse is a Windows x64 reverse-engineering workbench written in C++.
It provides PE parsing, process and module inspection, disassembly, string and
pattern scanning, cross-reference analysis, a graphical interface, and an
interactive command-line shell. An optional AI client can send selected
analysis context to a local or OpenAI-compatible provider.

The project is under active development. Interfaces and analysis results may
change between releases.

## Repository layout

- `src/`: application and analysis source code
- `installer/`: Windows installer source and resources
- `tests/fixtures/crackme/`: small local analysis fixture
- `scripts/`: build and installation helpers
- `web/app/`: official React/Vite website
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

## CLI

```powershell
.\build\bin\Release\OpenReverse.exe --help
.\build\bin\Release\OpenReverse.exe
```

The shell supports opening PE files, attaching to processes, disassembly,
function analysis, strings, XREFs, reports, and optional AI-assisted queries.

## Website

The official website lives in `web/app`.

```powershell
cd web\app
npm.cmd ci
npm.cmd run dev
```

Use `npm.cmd run build` to create the production bundle in `web/app/dist`.

## License

This project is distributed under the MIT License. See `LICENSE`.
