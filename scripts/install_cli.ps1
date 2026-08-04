# ============================================================================
# OpenReverse CLI installer (PowerShell)
# Installs 'OpenReverse.exe' to %USERPROFILE%\.openreverse\bin and updates PATH
# ============================================================================

$ErrorActionPreference = 'Stop'

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                       OPENREVERSE CLI INSTALLER                              " -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Note: The OpenReverse CLI is designed to be installed and run via Shell only." -ForegroundColor DarkGray
Write-Host ""

# 1. Locate source binary
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
$sourceExe = Join-Path $projectDir "build\bin\Release\OpenReverse.exe"
if (-not (Test-Path $sourceExe)) {
    $sourceExe = Join-Path $projectDir "build\Release\OpenReverse.exe"
}
if (-not (Test-Path $sourceExe)) {
    Write-Host "[-] OpenReverse.exe not found in build directory. Building now..." -ForegroundColor Yellow
    & cmake --build (Join-Path $projectDir "build") --config Release --parallel
    $sourceExe = Join-Path $projectDir "build\bin\Release\OpenReverse.exe"
}

if (-not (Test-Path $sourceExe)) {
    Write-Host "[X] ERROR: Could not locate OpenReverse.exe. Please run cmake --build build --config Release first." -ForegroundColor Red
    exit 1
}

# 2. Create Target Directory in %USERPROFILE%\.openreverse\bin
$targetDir = Join-Path $env:USERPROFILE ".openreverse\bin"
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    Write-Host "[+] Created CLI binary directory: $targetDir" -ForegroundColor Green
}

# 3. Copy OpenReverse.exe
$destExe = Join-Path $targetDir "OpenReverse.exe"
Copy-Item -Path $sourceExe -Destination $destExe -Force
Write-Host "[+] Installed OpenReverse.exe CLI to: $destExe" -ForegroundColor Green

# 4. Add to User PATH environment variable
$currentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$pathParts = $currentPath -split ';' | Where-Object { $_ -ne '' }

if ($pathParts -notcontains $targetDir) {
    $newPath = ($pathParts + $targetDir) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Host "[+] Added $targetDir to Windows User PATH environment variable!" -ForegroundColor Green
} else {
    Write-Host "[*] $targetDir is already configured in Windows User PATH." -ForegroundColor Yellow
}

# 5. Update current session PATH
$env:Path = "$targetDir;$env:Path"

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  [SUCCESS] OPENREVERSE CLI IS INSTALLED AND READY IN YOUR SHELL!               " -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Run 'openreverse' in any terminal to launch the CLI." -ForegroundColor White
Write-Host "  Commands available:" -ForegroundColor White
Write-Host "    • /login          -> Quick Connect Wizard (Free Local Ollama / LM Studio)" -ForegroundColor Gray
Write-Host "    • /anti-debug     -> Scan PEB & kernel trap flags" -ForegroundColor Gray
Write-Host "    • /shield         -> Protect against VM/Sandbox & active anti-debugging" -ForegroundColor Gray
Write-Host "    • /anti-vm        -> Analyze RDTSC timing & hypervisor artifacts" -ForegroundColor Gray
Write-Host "    • /hub            -> Browse installed extensions" -ForegroundColor Gray
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
