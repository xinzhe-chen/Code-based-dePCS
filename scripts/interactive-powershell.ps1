param(
    [switch]$NoPause
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $ScriptRoot "..")).Path
Set-Location -LiteralPath $RepoRoot
$Script:QueuedInput = [System.Collections.Generic.Queue[string]]::new()
foreach ($item in $input) {
    $Script:QueuedInput.Enqueue([string]$item)
}

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host "== $Message =="
}

function Write-Step {
    param([string]$Message)
    Write-Host "[pq_dSNARK] $Message"
}

function Read-Text {
    param(
        [string]$Prompt,
        [string]$Default = ""
    )
    if ($Default.Length -gt 0) {
        Write-Host -NoNewline "$Prompt [$Default]: "
    } else {
        Write-Host -NoNewline "${Prompt}: "
    }
    if ($Script:QueuedInput.Count -gt 0) {
        $line = $Script:QueuedInput.Dequeue()
        Write-Host $line
    } else {
        $line = [Console]::In.ReadLine()
    }
    if ($null -eq $line) {
        return $Default
    }
    $line = $line.Trim()
    if ($line.Length -eq 0) {
        return $Default
    }
    return $line
}

function Read-Choice {
    param(
        [string]$Prompt,
        [string]$Default,
        [string[]]$Allowed
    )
    while ($true) {
        $value = (Read-Text -Prompt $Prompt -Default $Default).ToLowerInvariant()
        if ($Allowed -contains $value) {
            return $value
        }
        Write-Host "Invalid value '$value'. Expected one of: $($Allowed -join ', ')"
    }
}

function Confirm-Choice {
    param(
        [string]$Prompt,
        [bool]$Default = $false
    )
    $defaultText = if ($Default) { "y" } else { "n" }
    while ($true) {
        $value = (Read-Text -Prompt "$Prompt [y/n]" -Default $defaultText).ToLowerInvariant()
        if ($value -eq "y" -or $value -eq "yes") { return $true }
        if ($value -eq "n" -or $value -eq "no") { return $false }
        Write-Host "Please answer y or n."
    }
}

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Add-CargoBinToPath {
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if ((Test-Path -LiteralPath $cargoBin) -and -not (($env:Path -split ";") -contains $cargoBin)) {
        $env:Path = "$cargoBin;$env:Path"
    }
}

function Invoke-Checked {
    param(
        [string]$File,
        [string[]]$Arguments = @()
    )
    Write-Host "> $File $($Arguments -join ' ')"
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "command failed with exit code ${LASTEXITCODE}: $File $($Arguments -join ' ')"
    }
}

function Install-With-WindowsPackageManager {
    param(
        [string]$WingetId,
        [string]$ChocolateyName,
        [string[]]$WingetArguments = @()
    )
    if (Test-Command "winget") {
        $args = @("install", "--id", $WingetId, "-e", "--accept-package-agreements", "--accept-source-agreements")
        $args += $WingetArguments
        Invoke-Checked "winget" $args
        return
    }
    if (Test-Command "choco") {
        Invoke-Checked "choco" @("install", $ChocolateyName, "-y")
        return
    }
    throw "neither winget nor Chocolatey is available; install the missing tool manually and rerun this menu"
}

function Test-MsvcTools {
    if (Test-Command "cl") {
        return $true
    }
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere)) {
        return $false
    }
    & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Out-Null
    return $LASTEXITCODE -eq 0
}

function Show-Preflight {
    Add-CargoBinToPath
    Write-Section "Preflight"
    $checks = @(
        @("git", (Test-Command "git")),
        @("rustc", (Test-Command "rustc")),
        @("cargo", (Test-Command "cargo")),
        @("rustup", (Test-Command "rustup")),
        @("MSVC C++ build tools", (Test-MsvcTools))
    )
    foreach ($check in $checks) {
        $state = if ($check[1]) { "ok" } else { "missing" }
        Write-Host ("{0,-24} {1}" -f $check[0], $state)
    }
    if (Test-Command "cargo") {
        Invoke-Checked "cargo" @("--version")
    }
    Write-Host "repo: $RepoRoot"
}

function Ensure-Toolchain {
    param([bool]$Install)
    Add-CargoBinToPath
    $missing = @()
    foreach ($name in @("git", "rustc", "cargo")) {
        if (-not (Test-Command $name)) {
            $missing += $name
        }
    }
    if ((-not (Test-MsvcTools)) -and -not ($missing -contains "MSVC C++ build tools")) {
        $missing += "MSVC C++ build tools"
    }
    if ($missing.Count -eq 0) {
        Write-Step "toolchain preflight passed"
    } elseif ($Install) {
        Write-Step "installing missing tools: $($missing -join ', ')"
        if (($missing -contains "git")) {
            Install-With-WindowsPackageManager -WingetId "Git.Git" -ChocolateyName "git"
        }
        if (($missing -contains "rustc") -or ($missing -contains "cargo")) {
            Install-With-WindowsPackageManager -WingetId "Rustlang.Rustup" -ChocolateyName "rustup.install"
            Add-CargoBinToPath
        }
        if ($missing -contains "MSVC C++ build tools") {
            Install-With-WindowsPackageManager `
                -WingetId "Microsoft.VisualStudio.2022.BuildTools" `
                -ChocolateyName "visualstudio2022buildtools" `
                -WingetArguments @("--override", "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended")
        }
    } else {
        throw "missing required tools: $($missing -join ', '); choose menu option 2 to install detected missing dependencies"
    }

    Add-CargoBinToPath
    foreach ($name in @("git", "rustc", "cargo")) {
        if (-not (Test-Command $name)) {
            throw "$name is still missing after setup"
        }
    }
    if (Test-Command "rustup") {
        Invoke-Checked "rustup" @("show")
        Invoke-Checked "rustup" @("component", "add", "rustfmt", "clippy")
    }
}

function Get-ExperimentBinary {
    param([bool]$Release)
    if ($Release) {
        return Join-Path $RepoRoot "target\release\pq-experiments.exe"
    }
    return Join-Path $RepoRoot "target\debug\pq-experiments.exe"
}

function Build-ExperimentBinary {
    param([bool]$Release)
    $args = @("build", "-p", "pq-experiments")
    if ($Release) {
        $args += "--release"
    }
    Invoke-Checked "cargo" $args
    $bin = Get-ExperimentBinary -Release $Release
    if (-not (Test-Path -LiteralPath $bin)) {
        throw "expected experiment binary was not produced: $bin"
    }
}

function Invoke-ProofWizard {
    Ensure-Toolchain -Install:$false
    Write-Section "Proof Experiment Wizard"
    Write-Host "This opens the Rust CLI prompt for local, loopback network proof, or TCP demo runs."
    Write-Step "building debug pq-experiments"
    Build-ExperimentBinary -Release:$false
    $bin = Get-ExperimentBinary -Release:$false
    Invoke-Checked $bin @("interactive")
}

function Split-CsvIntegers {
    param([string]$Value)
    return @($Value.Split(",") | ForEach-Object { [int]($_.Trim()) })
}

function Show-BenchmarkCorePlan {
    param(
        [string]$Runner,
        [string]$Workers
    )
    if ($Runner -eq "local") {
        return
    }
    $workerValues = Split-CsvIntegers -Value $Workers
    if ($workerValues.Count -le 1) {
        return
    }
    $maxWorkers = ($workerValues | Measure-Object -Maximum).Maximum
    $hostCores = [Environment]::ProcessorCount
    $coresPerWorker = [Math]::Floor($hostCores / $maxWorkers)
    Write-Step "network scaling core plan: host_logical_cores=$hostCores max_workers=$maxWorkers cores_per_worker=$coresPerWorker"
    if ($coresPerWorker -lt 1) {
        throw "host has too few logical cores for the requested max worker count"
    }
}

function Invoke-BenchmarkWizard {
    Ensure-Toolchain -Install:$false
    Write-Section "Performance Benchmark Wizard"
    Write-Host "Each benchmark job runs one real end-to-end prove+verify path. Correctness tests are not included."
    Write-Host "During execution, pq-experiments prints an exact completed-jobs progress bar before and after each real job."

    $paperPreset = Confirm-Choice -Prompt "Use the full paper-quality benchmark grid" -Default:$false
    $runner = Read-Choice -Prompt "runner [local|network|both]" -Default "both" -Allowed @("local", "network", "both")
    $args = @("benchmark", "--runner", $runner, "--repeats", "1")

    if ($paperPreset) {
        $args += "--paper-preset"
    } else {
        $nRange = Read-Text -Prompt "circuit size exponent range n for nv=2^n" -Default "2..5"
        $workers = Read-Text -Prompt "worker counts, comma separated and including 1" -Default "1,2,4"
        $pcsQueries = Read-Text -Prompt "PCS query count" -Default "1"
        Show-BenchmarkCorePlan -Runner $runner -Workers $workers
        $args += @("--n-range", $nRange, "--workers", $workers, "--pcs-queries", $pcsQueries)
    }

    $compileFigures = Confirm-Choice -Prompt "Compile paper figures after the run" -Default:$false
    if ($compileFigures) {
        $compiler = Read-Choice -Prompt "figure compiler [auto|pdflatex|tectonic]" -Default "auto" -Allowed @("auto", "pdflatex", "tectonic")
        $args += @("--compile-figures", "--figure-compiler", $compiler)
    }
    $outDir = Read-Text -Prompt "output directory" -Default "results"
    $args += @("--out", $outDir)

    Write-Step "building release pq-experiments"
    Build-ExperimentBinary -Release:$true
    $bin = Get-ExperimentBinary -Release:$true
    Invoke-Checked $bin $args
}

function Get-LatestBenchmarkDir {
    $results = Join-Path $RepoRoot "results"
    if (-not (Test-Path -LiteralPath $results)) {
        return ""
    }
    $latest = Get-ChildItem -LiteralPath $results -Directory -Filter "bench-*" |
        Sort-Object LastWriteTimeUtc |
        Select-Object -Last 1
    if ($null -eq $latest) {
        return ""
    }
    return $latest.FullName
}

function Invoke-VerifyWizard {
    Ensure-Toolchain -Install:$false
    Write-Section "Verify Results Wizard"
    $defaultDir = Get-LatestBenchmarkDir
    $dir = Read-Text -Prompt "benchmark result directory" -Default $defaultDir
    if ($dir.Length -eq 0) {
        throw "no benchmark result directory selected"
    }
    $format = Read-Choice -Prompt "report format [json|csv]" -Default "json" -Allowed @("json", "csv")
    $paperQuality = Confirm-Choice -Prompt "apply paper-quality release gate" -Default:$false

    Write-Step "building debug pq-experiments"
    Build-ExperimentBinary -Release:$false
    $bin = Get-ExperimentBinary -Release:$false
    $args = @("verify-results", $dir, "--format", $format)
    if ($paperQuality) {
        $args += "--paper-quality"
    }
    Invoke-Checked $bin $args
}

function Show-Menu {
    Write-Section "pq_dSNARK interactive entrypoint (PowerShell)"
    Write-Host "1. Preflight dependency check"
    Write-Host "2. Install/check missing dependencies"
    Write-Host "3. Proof experiment wizard"
    Write-Host "4. Performance benchmark wizard"
    Write-Host "5. Verify benchmark results"
    Write-Host "0. Exit"
}

function Invoke-Menu {
    while ($true) {
        Show-Menu
        $choice = Read-Choice -Prompt "Select an action" -Default "3" -Allowed @("0", "1", "2", "3", "4", "5")
        switch ($choice) {
            "0" { return }
            "1" { Show-Preflight }
            "2" { Ensure-Toolchain -Install:$true; Show-Preflight }
            "3" { Invoke-ProofWizard }
            "4" { Invoke-BenchmarkWizard }
            "5" { Invoke-VerifyWizard }
        }
    }
}

$exitCode = 0
try {
    Invoke-Menu
} catch {
    $exitCode = 1
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    if (-not $NoPause) {
        Write-Host ""
        Write-Host -NoNewline "Press Enter to exit..."
        [Console]::In.ReadLine() | Out-Null
    }
}
exit $exitCode
