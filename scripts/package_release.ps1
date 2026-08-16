[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$OutputDirectory = 'dist'
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$projectFile = Join-Path $repositoryRoot 'CMakeLists.txt'
$project = Get-Content -LiteralPath $projectFile -Raw
if ($project -notmatch 'project\(OpenReverse VERSION ([0-9]+\.[0-9]+\.[0-9]+)') {
    throw 'Could not read the OpenReverse version from CMakeLists.txt'
}
$version = $Matches[1]

$binaryDirectory = Join-Path $repositoryRoot "build/windows-x64/bin/$Configuration"
$application = Join-Path $binaryDirectory 'OpenReverse.exe'
$installer = Join-Path $binaryDirectory "OpenReverse-$version-Setup.exe"
if (!(Test-Path -LiteralPath $application -PathType Leaf)) {
    throw "Missing application build: $application"
}
if (!(Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "Missing installer build: $installer"
}

if (![IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot $OutputDirectory
}
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$stagingDirectory = Join-Path $temporaryRoot ("OpenReverse-$version-Portable-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stagingDirectory | Out-Null

try {
    Copy-Item -LiteralPath $application -Destination $stagingDirectory
    $distributionDocuments = @('README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md') |
        ForEach-Object { Join-Path $repositoryRoot $_ }
    Copy-Item -LiteralPath $distributionDocuments -Destination $stagingDirectory

    $installerOutput = Join-Path $outputPath "OpenReverse-$version-Setup.exe"
    $portableOutput = Join-Path $outputPath "OpenReverse-$version-Portable.zip"
    $checksumOutput = Join-Path $outputPath 'SHA256SUMS.txt'
    Copy-Item -LiteralPath $installer -Destination $installerOutput -Force
    if (Test-Path -LiteralPath $portableOutput) {
        Remove-Item -LiteralPath $portableOutput -Force
    }
    Compress-Archive -Path (Join-Path $stagingDirectory '*') -DestinationPath $portableOutput

    $checksumLines = foreach ($file in @($installerOutput, $portableOutput)) {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
        "$hash  $([IO.Path]::GetFileName($file))"
    }
    [IO.File]::WriteAllLines($checksumOutput, $checksumLines, [Text.UTF8Encoding]::new($false))

    [pscustomobject]@{
        Version = $version
        Installer = $installerOutput
        Portable = $portableOutput
        Checksums = $checksumOutput
    }
}
finally {
    $resolvedStaging = [IO.Path]::GetFullPath($stagingDirectory)
    $temporaryPrefix = $temporaryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if ($resolvedStaging.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedStaging)) {
        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
}
