param(
    [string]$Configuration = 'Release',
    [string]$OutputDirectory = 'dist',
    [string]$BinaryDirectory = ''
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$versionFile = Join-Path $repositoryRoot 'VERSION'
$version = (Get-Content -LiteralPath $versionFile -Raw).Trim()
if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') {
    throw 'VERSION does not contain a valid OpenReverse release version'
}

if ([string]::IsNullOrWhiteSpace($BinaryDirectory)) {
    $candidates = @(
        (Join-Path $repositoryRoot "build/bin/$Configuration"),
        (Join-Path $repositoryRoot "build/windows-x64/bin/$Configuration")
    )
    $newestTime = [DateTime]::MinValue
    foreach ($c in $candidates) {
        $exe = Join-Path $c 'OpenReverse.exe'
        if (Test-Path -LiteralPath $exe -PathType Leaf) {
            $item = Get-Item -LiteralPath $exe
            if ($item.LastWriteTimeUtc -gt $newestTime) {
                $newestTime = $item.LastWriteTimeUtc
                $BinaryDirectory = $c
            }
        }
    }
}

if ([string]::IsNullOrWhiteSpace($BinaryDirectory) -or !(Test-Path -LiteralPath $BinaryDirectory)) {
    throw "Missing binary directory for configuration $Configuration"
}

$application = Join-Path $BinaryDirectory 'OpenReverse.exe'
$installer = Join-Path $BinaryDirectory "OpenReverse-$version-Setup.exe"
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
