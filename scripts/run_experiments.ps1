param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RemainingArgs
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

function Write-Step {
    param([string] $Message)
    Write-Host "[experiment] $Message"
}

if ($RemainingArgs.Count -eq 0 -or $RemainingArgs[0] -eq "-h" -or $RemainingArgs[0] -eq "--help") {
    @"
Usage:
  scripts\run_experiments.ps1 interactive
  scripts\run_experiments.ps1 <r1cs|plonkish> [--workers N] [--size N] [--pcs-queries N] [--format json|csv] [--case positive|negative|both]
  scripts\run_experiments.ps1 net-demo [--workers N] [--format json|csv]
  scripts\run_experiments.ps1 worker --addr HOST:PORT --id N
  scripts\run_experiments.ps1 master --addrs HOST1:PORT,HOST2:PORT [--ids 0,1] [--shutdown]
"@
    exit 0
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo is required but was not found on PATH"
}

Write-Step "workspace: $RepoRoot"
Write-Step "building pq-experiments"
cargo build -p pq-experiments

$Bin = Join-Path $RepoRoot "target\debug\pq-experiments.exe"
Write-Step "running: pq-experiments $($RemainingArgs -join ' ')"
& $Bin @RemainingArgs
Write-Step "done"
exit $LASTEXITCODE
