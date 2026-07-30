# ============================================================================
# OPENREVERSE / KYV Studio - Universal Shell CLI Installer (PowerShell)
# Installs openreverse.exe to %USERPROFILE%\.openreverse\bin and adds it to PATH
# ============================================================================

$ErrorActionPreference = 'Stop'

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                OPENREVERSE Universal Shell Installer (v2.0)                    " -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Determine Source & Target Directories
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceExe = Join-Path $scriptDir "build_ninja\bin\openreverse.exe"
$sourceKyv = Join-Path $scriptDir "build_ninja\bin\KYV.exe"

if (-not (Test-Path $sourceExe)) {
    Write-Host "[-] openreverse.exe not found in build_ninja\bin. Rebuilding first..." -ForegroundColor Yellow
    & "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    & cmake --build (Join-Path $scriptDir "build_ninja") --config Release
}

$targetDir = Join-Path $env:USERPROFILE ".openreverse\bin"
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    Write-Host "[+] Created directory: $targetDir" -ForegroundColor Green
}

# 2. Copy binaries
$destExe = Join-Path $targetDir "openreverse.exe"
$destKyv = Join-Path $targetDir "KYV.exe"

Copy-Item -Path $sourceExe -Destination $destExe -Force
if (Test-Path $sourceKyv) {
    Copy-Item -Path $sourceKyv -Destination $destKyv -Force
}
Write-Host "[+] Installed openreverse.exe to $targetDir" -ForegroundColor Green

# 3. Add to Windows User PATH environment variable
$currentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$pathParts = $currentPath -split ';' | Where-Object { $_ -ne '' }

if ($pathParts -notcontains $targetDir) {
    $newPath = ($pathParts + $targetDir) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Host "[+] Added $targetDir to Windows User PATH environment variable!" -ForegroundColor Green
} else {
    Write-Host "[*] $targetDir is already in your Windows User PATH." -ForegroundColor Yellow
}

# 4. Also update current process PATH so it works in this shell session
$env:Path = "$targetDir;$env:Path"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "[+] INSTALLATION COMPLETE! You can now type 'openreverse' in ANY shell/terminal!" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
