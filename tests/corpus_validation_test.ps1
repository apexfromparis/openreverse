param(
    [Parameter(Mandatory = $true)]
    [string]$Validator,

    [Parameter(Mandatory = $true)]
    [string]$Fixture
)

$ErrorActionPreference = 'Stop'
$testDirectory = Join-Path ([System.IO.Path]::GetTempPath()) (
    'openreverse-corpus-' + [Guid]::NewGuid().ToString('N') + '-échantillon')
$report = Join-Path $testDirectory 'résultat.json'
$sentinel = Join-Path $testDirectory 'execution-sentinel.txt'
$previousSentinel = $env:OPENREVERSE_EXECUTION_SENTINEL

try {
    New-Item -ItemType Directory -Path $testDirectory | Out-Null
    Copy-Item -LiteralPath $Fixture -Destination (Join-Path $testDirectory 'valide-分析.exe')
    [System.IO.File]::WriteAllBytes((Join-Path $testDirectory 'malformed.exe'),
        [byte[]](0x4D, 0x5A, 0x00, 0x00, 0xFF))
    $env:OPENREVERSE_EXECUTION_SENTINEL = $sentinel

    & $Validator $testDirectory --output $report
    if ($LASTEXITCODE -ne 0) {
        throw "Corpus validator failed with exit code $LASTEXITCODE"
    }
    if (Test-Path -LiteralPath $sentinel) {
        throw 'Corpus validation executed an analyzed fixture.'
    }

    $json = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
    if (-not $json.static_analysis_only) { throw 'Static-analysis invariant missing from report.' }
    if ($json.summary.candidates -ne 2) { throw 'Expected exactly two corpus candidates.' }
    if ($json.summary.success -lt 1) { throw 'Valid PE was not analyzed successfully.' }
    if ($json.summary.failure -lt 1) { throw 'Malformed PE was not reported as a failure.' }
    if ($json.summary.exceptions -ne 0) { throw 'Corpus validator reported an exception.' }
    $valid = $json.files | Where-Object { $_.status -eq 'success' } | Select-Object -First 1
    if ($null -eq $valid.sha256 -or $valid.sha256.Length -ne 64) {
        throw 'Valid PE report is missing its SHA-256.'
    }
    if ($null -eq $valid.timings_ms.cfg) { throw 'CFG timing is missing.' }
}
finally {
    if ($null -eq $previousSentinel) {
        Remove-Item Env:OPENREVERSE_EXECUTION_SENTINEL -ErrorAction SilentlyContinue
    }
    else {
        $env:OPENREVERSE_EXECUTION_SENTINEL = $previousSentinel
    }
    Remove-Item -LiteralPath $testDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
