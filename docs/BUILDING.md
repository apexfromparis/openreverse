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
ctest --test-dir build/windows-x64 -C Release --output-on-failure
```

`OpenReverse.Core` exercises PE mapping, bounded memory reads, disassembly,
function and CFG discovery, typed cross-references, patterns, scheduling,
database publication, and inferred data candidates. CMake also builds
`OpenReverseTestFixture.exe`, a small purpose-written PE used by CLI smoke
checks.

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
