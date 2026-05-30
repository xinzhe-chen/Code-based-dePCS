param(
    [string] $Sizes = "",
    [string] $NvPowers = "2,3,4",
    [string] $NvRange = "",
    [string] $Workers = "1,2,4",
    [int] $PcsQueries = 3,
    [string] $OutDir = "results"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

function Write-Step {
    param([string] $Message)
    Write-Host "[benchmark] $Message"
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo is required but was not found on PATH"
}

Write-Step "workspace: $RepoRoot"
Write-Step "building pq-experiments"
cargo build -p pq-experiments

$Bin = Join-Path $RepoRoot "target\debug\pq-experiments.exe"
$BenchArgs = @("benchmark")
if ($Sizes -ne "") {
    Write-Step "size selection: direct sizes $Sizes"
    $BenchArgs += @("--sizes", $Sizes)
} elseif ($NvRange -ne "") {
    Write-Step "size selection: nv=2^n for n in $NvRange"
    $BenchArgs += @("--nv-range", $NvRange)
} else {
    Write-Step "size selection: nv=2^n for n in $NvPowers"
    $BenchArgs += @("--nv-powers", $NvPowers)
}
$BenchArgs += @("--workers", $Workers, "--pcs-queries", "$PcsQueries", "--out", $OutDir)
Write-Step "running benchmark workers=$Workers pcs_queries=$PcsQueries out=$OutDir"
& $Bin @BenchArgs
Write-Step "done"
