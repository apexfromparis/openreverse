# Building OpenReverse

## Prerequisites

OpenReverse supports Windows x64. Install:

- Windows 10 or later
- Visual Studio 2022 with the Desktop development with C++ workload
- CMake 3.23 or later
- Git

The initial configure downloads the exact Dear ImGui, Capstone, and
nlohmann/json revisions declared in `CMakeLists.txt`. Subsequent builds can use
the local FetchContent trees without checking for updates.

## Configure and build

Run these commands from the repository root in PowerShell:

```powershell
cmake --preset windows-x64
cmake --build --preset windows-x64-release --parallel
```

The preset uses Visual Studio 2022 and writes its build tree to
`build/windows-x64`. The Release application and installer are created in
`build/windows-x64/bin/Release`.

## Test

```powershell
ctest --preset windows-x64-release
cmake --build --preset windows-x64-debug --parallel
ctest --preset windows-x64-debug
```

`OpenReverse.Core` exercises PE mapping, bounded memory reads, disassembly,
function and CFG discovery, typed cross-references, patterns, scheduling,
database publication, inferred data candidates, optional DIA symbols/types,
parser mutations, Version Intelligence scaling, extension manifests, ABI
compatibility, loader failures, callbacks, and extension project state.
`OpenReverse.StaticOpen` and `OpenReverse.CorpusValidation` protect the static
analysis invariant. CMake also builds `OpenReverseTestFixture.exe`, a small
purpose-written PE used by CLI and corpus checks.

First-party targets compile with `/W4`; vendored dependencies do not inherit
that policy. Targeted MSVC code analysis can be enabled in a separate build with
`-DOPENREVERSE_ENABLE_MSVC_ANALYZE=ON`.

## Extension SDK example

The minimal Community example can be compiled without OpenReverse internals:

```powershell
cmake -S examples/hello_extension -B build/hello-extension
cmake --build build/hello-extension --config Release
```

It includes only `sdk/include/openreverse/extension.h`. The main test build also
compiles the example and purpose-built invalid DLL fixtures, but neither the
application nor the installer bundles them. See [Extensions](EXTENSIONS.md).

## Smoke checks

The application uses the Windows GUI subsystem, so PowerShell automation should
wait explicitly:

```powershell
$app = 'build/windows-x64/bin/Release/OpenReverse.exe'
$result = Start-Process $app -ArgumentList '--help' -Wait -PassThru
if ($result.ExitCode -ne 0) { throw 'OpenReverse --help failed' }
```

The installer is `OpenReverse-2.0.0-Setup.exe`. Built executables are ignored by
Git and should be published as release assets rather than committed.

The developer-only corpus executable is `OpenReverseValidation.exe`:

```powershell
build\windows-x64\bin\Release\OpenReverseValidation.exe C:\path\to\corpus `
  --output openreverse-validation.json
```

It statically parses/maps common PE files with explicit budgets and writes an
ignored JSON report. It never launches corpus candidates.

## Package and publish a Community release

After the Release build and tests pass, the packaging script creates the three
canonical release artifacts from the version declared in `CMakeLists.txt`:

```powershell
.\scripts\package_release.ps1 -OutputDirectory dist
```

The output is:

- `OpenReverse-x.y.z-Setup.exe`
- `OpenReverse-x.y.z-Portable.zip`
- `SHA256SUMS.txt`

Pushing a protected tag named exactly `vx.y.z` runs the Windows Release workflow.
The workflow rejects a tag that differs from the CMake project version, rebuilds
and tests Community, packages the artifacts with the same script, and publishes
them through GitHub Releases. Release executables and archives remain untracked.

The current pipeline provides reproducible checksums but does not yet provide
Windows code signing or a signed update manifest. Automatic updating must remain
disabled until trusted signing, staged installation, and rollback are tested.

## Local CLI installation

After a successful build, `scripts/install_cli.ps1` copies the shared executable
to `%LOCALAPPDATA%\OpenReverse\bin` and adds that directory to the user PATH.
Pass `-Build` to configure and build first:

```powershell
.\scripts\install_cli.ps1 -Build
```
