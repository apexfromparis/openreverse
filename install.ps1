# ==============================================================================
# OPENREVERSE Studio CLI - Universal Windows Installer Script
# Usage: irm https://raw.githubusercontent.com/apexfromparis/powerfull-ida/main/install.ps1 | iex
# ==============================================================================

$ErrorActionPreference = "Stop"

$installDir = "$env:USERPROFILE\.openreverse\bin"
if (-not (Test-Path -Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

Write-Host "================================================================================="
Write-Host "   ___  ____  _____ _   _ ____  _____ __     _____ ____  ____  _____ "
Write-Host "  / _ \|  _ \| ____| \ | |  _ \| ____|\ \   / / ____|  _ \/ ___|| ____|"
Write-Host " | | | | |_) |  _| |  \| | |_) |  _|   \ \ / /|  _| | |_) \___ \|  _|  "
Write-Host " | |_| |  __/| |___| |\  |  _ <| |___   \ V / | |___|  _ < ___) | |___ "
Write-Host "  \___/|_|   |_____|_| \_|_| \_\_____|   \_/  |_____|_| \_\____/|_____|"
Write-Host "---------------------------------------------------------------------------------"
Write-Host "   OPENREVERSE Studio CLI - Universal Windows Installer"
Write-Host "================================================================================="

# Try to find locally compiled binary first (for development / local installation)
$localBin = Join-Path $PSScriptRoot "build_ninja\bin\OpenReverse.exe"
if (-not (Test-Path -Path $localBin)) {
    $localBin = Join-Path $PSScriptRoot "build\bin\Release\OpenReverse.exe"
}

$destBin = Join-Path $installDir "OpenReverse.exe"

if (Test-Path -Path $localBin) {
    Write-Host "[*] Installing local build from: $localBin"
    Copy-Item -Path $localBin -Destination $destBin -Force
} else {
    Write-Host "[*] Downloading latest release from GitHub..."
    $releaseUrl = "https://github.com/apexfromparis/powerfull-ida/releases/latest/download/OpenReverse.exe"
    try {
        Invoke-WebRequest -Uri $releaseUrl -OutFile $destBin -UseBasicParsing
    } catch {
        Write-Warning "Could not download from GitHub release ($releaseUrl). Make sure a release binary is published."
        exit 1
    }
}

# Ensure PATH contains installDir
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$installDir*") {
    $newPath = "$userPath;$installDir"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    $env:Path = "$env:Path;$installDir"
    Write-Host "[+] Added $installDir to User PATH."
} else {
    Write-Host "[+] PATH already configured."
}

Write-Host "---------------------------------------------------------------------------------"
Write-Host " [SUCCESS] OPENREVERSE CLI installed to: $destBin"
Write-Host " Open a new PowerShell/CMD window and type: OpenReverse"
Write-Host "================================================================================="
