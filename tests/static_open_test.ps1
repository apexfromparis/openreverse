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
}
