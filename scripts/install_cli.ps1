[CmdletBinding()]
param(
    [switch]$Build
)

$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDirectory = Split-Path -Parent $scriptDirectory
$sourceExecutable = Join-Path $projectDirectory 'build\windows-x64\bin\Release\OpenReverse.exe'

if ($Build -or !(Test-Path -LiteralPath $sourceExecutable)) {
    Push-Location $projectDirectory
    try {
        & cmake --preset windows-x64
        if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }

        & cmake --build --preset windows-x64-release --parallel
        if ($LASTEXITCODE -ne 0) { throw 'OpenReverse build failed.' }
    }
    finally {
        Pop-Location
    }
}

if (!(Test-Path -LiteralPath $sourceExecutable)) {
    throw "OpenReverse.exe was not found at $sourceExecutable"
}

$targetDirectory = Join-Path $env:LOCALAPPDATA 'OpenReverse\bin'
New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
Copy-Item -LiteralPath $sourceExecutable -Destination (Join-Path $targetDirectory 'OpenReverse.exe') -Force

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$pathEntries = @($userPath -split ';' | Where-Object { $_ })
if ($targetDirectory -notin $pathEntries) {
    [Environment]::SetEnvironmentVariable('Path', (($pathEntries + $targetDirectory) -join ';'), 'User')
}

Write-Host "OpenReverse installed in $targetDirectory"
Write-Host 'Open a new terminal and run: OpenReverse.exe --help'
