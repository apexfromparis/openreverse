param(
    [Parameter(Mandatory = $true)]
    [string]$Application,

    [Parameter(Mandatory = $true)]
    [string]$Fixture
)

$ErrorActionPreference = 'Stop'
$sentinel = Join-Path ([System.IO.Path]::GetTempPath()) (
    'openreverse-static-open-' + [Guid]::NewGuid().ToString('N') + '.txt')
$previousSentinel = $env:OPENREVERSE_EXECUTION_SENTINEL
$unicodeDirectory = Join-Path ([System.IO.Path]::GetTempPath()) (
    'openreverse-unicode-' + [Guid]::NewGuid().ToString('N') + '-échantillon')

try {
    $env:OPENREVERSE_EXECUTION_SENTINEL = $sentinel

    $open = Start-Process -FilePath $Application -ArgumentList @('open', $Fixture) `
        -NoNewWindow -Wait -PassThru
    if ($open.ExitCode -ne 0) {
        throw "Static open failed with exit code $($open.ExitCode)"
    }
    if (Test-Path -LiteralPath $sentinel) {
        throw 'Static open executed the supplied fixture.'
    }

    New-Item -ItemType Directory -Path $unicodeDirectory | Out-Null
    $unicodeFixture = Join-Path $unicodeDirectory 'cible-分析.exe'
    Copy-Item -LiteralPath $Fixture -Destination $unicodeFixture
    $unicodeOpen = Start-Process -FilePath $Application -ArgumentList @('open', $unicodeFixture) `
        -NoNewWindow -Wait -PassThru
    if ($unicodeOpen.ExitCode -ne 0) {
        throw "Static Unicode-path open failed with exit code $($unicodeOpen.ExitCode)"
    }
    if (Test-Path -LiteralPath $sentinel) {
        throw 'Static Unicode-path open executed the supplied fixture.'
    }

    $legacy = Start-Process -FilePath $Application `
        -ArgumentList @('--decompile-exe', $Fixture) -NoNewWindow -Wait -PassThru
    if ($legacy.ExitCode -eq 0) {
        throw 'Removed legacy execution command unexpectedly succeeded.'
    }
    if (Test-Path -LiteralPath $sentinel) {
        throw 'Removed legacy execution command executed the supplied fixture.'
    }
}
finally {
    if ($null -eq $previousSentinel) {
        Remove-Item Env:OPENREVERSE_EXECUTION_SENTINEL -ErrorAction SilentlyContinue
    }
    else {
        $env:OPENREVERSE_EXECUTION_SENTINEL = $previousSentinel
    }
    Remove-Item -LiteralPath $sentinel -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $unicodeDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
