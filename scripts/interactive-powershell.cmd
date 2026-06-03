@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "REPO_ROOT=%SCRIPT_DIR%.."
set "POWERSHELL_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "NO_PAUSE="

for %%A in (%*) do (
    if /I "%%~A"=="-NoPause" set "NO_PAUSE=1"
)

if not exist "%POWERSHELL_EXE%" (
    set "POWERSHELL_EXE=powershell.exe"
)

set "PAYLOAD_GUID="
for /f "skip=2 delims=" %%G in ('%POWERSHELL_EXE% -NoProfile -ExecutionPolicy Bypass -Command New-Guid') do if not defined PAYLOAD_GUID set "PAYLOAD_GUID=%%G"
set "PAYLOAD_GUID=%PAYLOAD_GUID: =%"
if not defined PAYLOAD_GUID set "PAYLOAD_GUID=%RANDOM%-%RANDOM%-%RANDOM%-%RANDOM%"
set "GENERATED_PS=%REPO_ROOT%\target\windows\interactive-powershell-%PAYLOAD_GUID%.generated.ps1"

set "PQ_DSNARK_CMD_SELF=%~f0"
set "PQ_DSNARK_GENERATED_PS=%GENERATED_PS%"
"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $cmd=$env:PQ_DSNARK_CMD_SELF; $out=$env:PQ_DSNARK_GENERATED_PS; New-Item -ItemType Directory -Force -Path (Split-Path -Parent $out) | Out-Null; $lines=Get-Content -LiteralPath $cmd; $marker=[Array]::IndexOf($lines, '# POWERSHELL_PAYLOAD_BEGIN'); if ($marker -lt 0) { throw 'missing PowerShell payload marker' }; $payload=$lines[($marker + 1)..($lines.Count - 1)]; Set-Content -LiteralPath $out -Value $payload -Encoding UTF8"
set "STATUS=%ERRORLEVEL%"
if not "%STATUS%"=="0" (
    echo.
    echo Failed to prepare embedded PowerShell payload. Exit code %STATUS%.
    if not defined NO_PAUSE pause
    exit /b %STATUS%
)

"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%GENERATED_PS%" %*
set "STATUS=%ERRORLEVEL%"

if not "%STATUS%"=="0" (
    echo.
    echo interactive-powershell exited with code %STATUS%.
    if not defined NO_PAUSE pause
)

exit /b %STATUS%
# POWERSHELL_PAYLOAD_BEGIN
param(
    [switch]$NoPause
)

$Script:RepoRoot = $null
$Script:QueuedInput = $null

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

    $hostPrompt = $Prompt
    if ($Default.Length -gt 0) {
        $hostPrompt = "$Prompt [$Default]"
    }

    if ($Script:QueuedInput.Count -gt 0) {
        Write-Host -NoNewline "${hostPrompt}: "
        $line = $Script:QueuedInput.Dequeue()
        Write-Host $line
    } else {
        try {
            $line = Read-Host $hostPrompt
        } catch {
            $line = [Console]::In.ReadLine()
        }
    }
    if ($null -eq $line) {
        throw "no interactive console input is available; rerun from a PowerShell terminal or use the documented bypass command"
    }
    $line = $line.Trim()
    if ($line.Length -eq 0) {
        return $Default
    }
    return $line
}

function Read-TextWithHiddenDefault {
    param(
        [string]$Prompt,
        [string]$Default
    )

    if ($Script:QueuedInput.Count -gt 0) {
        Write-Host -NoNewline "${Prompt}: "
        $line = $Script:QueuedInput.Dequeue()
        Write-Host $line
    } else {
        try {
            $line = Read-Host $Prompt
        } catch {
            $line = [Console]::In.ReadLine()
        }
    }
    if ($null -eq $line) {
        throw "no interactive console input is available; rerun from a PowerShell terminal or use the documented bypass command"
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

function Read-RequiredText {
    param([string]$Prompt)
    while ($true) {
        $value = Read-Text -Prompt $Prompt
        if ($value.Length -gt 0) {
            return $value
        }
        Write-Host "Value is required."
    }
}

function Read-RequiredChoice {
    param(
        [string]$Prompt,
        [string[]]$Allowed
    )
    while ($true) {
        $value = (Read-RequiredText -Prompt $Prompt).ToLowerInvariant()
        if ($Allowed -contains $value) {
            return $value
        }
        Write-Host "Invalid value '$value'. Expected one of: $($Allowed -join ', ')"
    }
}

function Confirm-RequiredChoice {
    param([string]$Prompt)
    while ($true) {
        $value = (Read-RequiredText -Prompt "$Prompt (y/n)").ToLowerInvariant()
        if ($value -eq "y" -or $value -eq "yes") { return $true }
        if ($value -eq "n" -or $value -eq "no") { return $false }
        Write-Host "Please answer y or n."
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

function Convert-PowerRangeToCsv {
    param([string]$Range)
    $parts = $Range -split "\.\.", 2
    if ($parts.Count -ne 2) {
        throw "power range must look like 0..2"
    }
    $start = [int]$parts[0].Trim()
    $end = [int]$parts[1].Trim()
    if ($start -gt $end) {
        throw "power range start must be <= end"
    }
    $values = @("1")
    for ($power = $start; $power -le $end; $power++) {
        $values += [string]([int64]1 -shl $power)
    }
    $uniqueValues = @($values | ForEach-Object { [int64]$_ } | Sort-Object -Unique)
    return ($uniqueValues -join ",")
}

function Get-BenchmarkRunnerVariantCount {
    param([string]$Runner)
    if ($Runner -eq "both") { return 2 }
    return 1
}

function Confirm-BenchmarkGrid {
    param(
        [string]$Runner,
        [Int64]$SizeCount,
        [string]$SizeLabel,
        [string]$Workers
    )
    $workerCount = (Split-CsvIntegers -Value $Workers).Count
    $runnerCount = Get-BenchmarkRunnerVariantCount -Runner $Runner
    $totalJobs = [Int64]$SizeCount * [Int64]$workerCount * 2 * [Int64]$runnerCount
    Write-Step "benchmark grid: sizes=$SizeLabel size_count=$SizeCount workers=$Workers total_jobs=$totalJobs"
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
    if ($Script:RepoRoot) {
        $localTools = Join-Path $Script:RepoRoot "target\tools"
        if ((Test-Path -LiteralPath $localTools) -and -not (($env:Path -split ";") -contains $localTools)) {
            $env:Path = "$localTools;$env:Path"
        }
    }
}

function Invoke-Checked {
    param(
        [string]$File,
        [string[]]$Arguments = @()
    )
    Write-Host "> $File $($Arguments -join ' ')"
    & $File @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
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

function Test-FigureCompiler {
    return (Test-Command "tectonic") -or (Test-Command "pdflatex")
}

function Set-TectonicCacheDir {
    if (-not $env:TECTONIC_CACHE_DIR) {
        $cacheDir = Join-Path $Script:RepoRoot "target\tectonic-cache"
        New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
        $env:TECTONIC_CACHE_DIR = $cacheDir
    }
}

function Install-FigureCompiler {
    if (Test-FigureCompiler) {
        return
    }
    $toolDir = Join-Path $Script:RepoRoot "target\tools"
    New-Item -ItemType Directory -Force -Path $toolDir | Out-Null
    Add-CargoBinToPath

    $errors = @()
    try {
        Write-Step "installing prebuilt tectonic figure compiler"
        Push-Location -LiteralPath $toolDir
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            $installer = (New-Object System.Net.WebClient).DownloadString("https://drop-ps1.fullyjustified.net")
            Invoke-Expression $installer
        } finally {
            Pop-Location
        }
    } catch {
        $errors += "official installer failed: $($_.Exception.Message)"
    }

    Add-CargoBinToPath
    if ((-not (Test-FigureCompiler)) -and (Test-Command "choco")) {
        try {
            Write-Step "installing tectonic with Chocolatey"
            Invoke-Checked "choco" @("install", "tectonic", "-y")
        } catch {
            $errors += "Chocolatey install failed: $($_.Exception.Message)"
        }
    }
    Add-CargoBinToPath
    if ((-not (Test-FigureCompiler)) -and (Test-Command "winget")) {
        try {
            Write-Step "installing tectonic with winget"
            Invoke-Checked "winget" @("install", "--id", "tectonic.tectonic", "-e", "--accept-package-agreements", "--accept-source-agreements")
        } catch {
            $errors += "winget install failed: $($_.Exception.Message)"
        }
    }
    Add-CargoBinToPath
    if (-not (Test-FigureCompiler)) {
        $detail = if ($errors.Count -gt 0) { ": $($errors -join '; ')" } else { "" }
        throw "no LaTeX figure compiler found after installing prebuilt tectonic$detail"
    }
    Set-TectonicCacheDir
}

function Show-Preflight {
    Add-CargoBinToPath
    Write-Section "Preflight"
    $checks = @(
        @("git", (Test-Command "git")),
        @("rustc", (Test-Command "rustc")),
        @("cargo", (Test-Command "cargo")),
        @("rustup", (Test-Command "rustup")),
        @("MSVC C++ build tools", (Test-MsvcTools)),
        @("LaTeX figure compiler", (Test-FigureCompiler))
    )
    foreach ($check in $checks) {
        $state = if ($check[1]) { "ok" } else { "missing" }
        Write-Host ("{0,-24} {1}" -f $check[0], $state)
    }
    if (Test-Command "cargo") {
        Invoke-Checked "cargo" @("--version")
    }
    Write-Host "repo: $Script:RepoRoot"
}

function Ensure-Toolchain {
    param(
        [bool]$Install,
        [bool]$NeedFigureCompiler = $false
    )
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
    if ($NeedFigureCompiler -and (-not (Test-FigureCompiler))) {
        $missing += "tectonic"
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
        if ($missing -contains "tectonic") {
            Install-FigureCompiler
        }
    } else {
        throw "missing required tools: $($missing -join ', '); choose menu option 1 to install detected missing dependencies"
    }

    Add-CargoBinToPath
    foreach ($name in @("git", "rustc", "cargo")) {
        if (-not (Test-Command $name)) {
            throw "$name is still missing after setup"
        }
    }
    if ($NeedFigureCompiler) {
        if (-not (Test-FigureCompiler)) {
            throw "LaTeX figure compiler is still missing; install tectonic or pdflatex and rerun this menu"
        }
        Set-TectonicCacheDir
    }
    if (Test-Command "rustup") {
        Invoke-Checked "rustup" @("show")
        if ($Install) {
            Invoke-Checked "rustup" @("component", "add", "rustfmt", "clippy")
        }
    }
}

function Ensure-ToolchainForAction {
    param([bool]$NeedFigureCompiler = $false)
    try {
        Ensure-Toolchain -Install:$false -NeedFigureCompiler:$NeedFigureCompiler
    } catch {
        Write-Host $_.Exception.Message
        if (Confirm-RequiredChoice -Prompt "Install missing dependencies now") {
            Ensure-Toolchain -Install:$true -NeedFigureCompiler:$NeedFigureCompiler
        } else {
            throw
        }
    }
}

function Get-ExperimentBinary {
    param([bool]$Release)
    if ($Release) {
        return Join-Path $Script:RepoRoot "target\release\pq-experiments.exe"
    }
    return Join-Path $Script:RepoRoot "target\debug\pq-experiments.exe"
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
    Ensure-ToolchainForAction
    Write-Section "Proof Experiment Wizard"
    Write-Host "Runs one positive proof experiment, saves real proof bundles under the new bench folder, and performs the initial verify once."
    $protocol = Read-RequiredChoice -Prompt "protocol r1cs|plonkish|both" -Allowed @("r1cs", "plonkish", "both")
    $runner = Read-RequiredChoice -Prompt "runner local|network" -Allowed @("local", "network")
    $nPower = Read-RequiredText -Prompt "circuit size exponent n for nv=2^n"
    $workers = Read-RequiredText -Prompt "worker count"
    $pcsQueries = "1"
    Write-Step "PCS queries fixed at 1 for fastest interactive runs"
    Write-Step "building release pq-experiments"
    Build-ExperimentBinary -Release:$true
    $bin = Get-ExperimentBinary -Release:$true
    Invoke-Checked $bin @(
        "proof-experiment",
        "--protocol", $protocol,
        "--runner", $runner,
        "--n", $nPower,
        "--workers", $workers,
        "--pcs-queries", $pcsQueries
    )
}

function Split-CsvIntegers {
    param([string]$Value)
    return @($Value.Split(",") | ForEach-Object { [int]($_.Trim()) })
}

function Get-MaxPowerOfTwoExponent {
    param([int]$Value)
    if ($Value -lt 1) {
        return 0
    }
    $exponent = 0
    $power = 1
    while (($power * 2) -le $Value) {
        $power *= 2
        $exponent += 1
    }
    return $exponent
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
    Ensure-ToolchainForAction
    Write-Section "Performance Benchmark Wizard"
    Write-Host "Each benchmark job runs one real end-to-end prove+verify path. Correctness tests are not included."
    Write-Host "During execution, pq-experiments prints an exact completed-jobs progress bar before and after each real job."
    $hostCores = [Environment]::ProcessorCount
    $hostWorkerMax = Get-MaxPowerOfTwoExponent -Value $hostCores
    Write-Step "detected host logical cores: $hostCores; host can support worker exponent up to $hostWorkerMax before circuit-size limits"

    $runner = Read-RequiredChoice -Prompt "runner local|network|both" -Allowed @("local", "network", "both")
    $args = @("benchmark", "--runner", $runner, "--repeats", "1")

    $nMin = [int](Read-TextWithHiddenDefault -Prompt "minimum circuit size exponent n for nv=2^n" -Default "8")
    $nMax = [int](Read-TextWithHiddenDefault -Prompt "maximum circuit size exponent n for nv=2^n" -Default "10")
    if ($nMin -gt $nMax) {
        throw "minimum circuit size exponent must be <= maximum circuit size exponent"
    }
    $nRange = "$nMin..$nMax"
    $sizeCount = [Int64]($nMax - $nMin + 1)
    $sizeLabel = "2^$nMin..2^$nMax"
    $defaultWorkerMax = [Math]::Min([Math]::Min($hostWorkerMax, $nMin), 3)
    $workerMin = [int](Read-TextWithHiddenDefault -Prompt "minimum worker exponent for workers=2^w" -Default "0")
    $workerMax = [int](Read-TextWithHiddenDefault -Prompt "maximum worker exponent for workers=2^w" -Default ([string]$defaultWorkerMax))
    if ($workerMin -gt $workerMax) {
        throw "minimum worker exponent must be <= maximum worker exponent"
    }
    $workerRange = "$workerMin..$workerMax"
    $workers = Convert-PowerRangeToCsv -Range $workerRange
    $pcsQueries = "1"
    Write-Step "PCS queries fixed at 1 for fastest interactive runs"
    Show-BenchmarkCorePlan -Runner $runner -Workers $workers
    $args += @("--n-range", $nRange, "--worker-power-range", $workerRange, "--pcs-queries", $pcsQueries)

    Confirm-BenchmarkGrid -Runner $runner -SizeCount $sizeCount -SizeLabel $sizeLabel -Workers $workers

    Write-Step "figure compilation is enabled by default"
    Ensure-ToolchainForAction -NeedFigureCompiler:$true
    $args += @("--compile-figures", "--figure-compiler", "auto")
    Write-Step "building release pq-experiments"
    Build-ExperimentBinary -Release:$true
    $bin = Get-ExperimentBinary -Release:$true
    Invoke-Checked $bin $args
}

function Get-LatestBenchmarkDir {
    $results = Join-Path $Script:RepoRoot "results"
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

function Invoke-SetupWizard {
    Write-Section "Environment Setup"
    Show-Preflight
    if (Confirm-Choice -Prompt "Install/check missing dependencies now" -Default:$false) {
        Ensure-Toolchain -Install:$true -NeedFigureCompiler:$true
        Show-Preflight
    }
    $debugBin = Get-ExperimentBinary -Release:$false
    if (Test-Path -LiteralPath $debugBin) {
        Write-Step "debug pq-experiments already built: $debugBin"
    } elseif (Confirm-Choice -Prompt "Build debug pq-experiments now" -Default:$true) {
        Ensure-ToolchainForAction
        Build-ExperimentBinary -Release:$false
    }
}

function Invoke-ResultsWizard {
    Ensure-ToolchainForAction
    Write-Section "Verify Experiments Wizard"
    Write-Host "Detects bench folders, shows which ones contain stored proof bundles, and verifies selected proofs without rewriting benchmark source artifacts."
    $resultsDir = Read-Text -Prompt "results directory" -Default "results"
    Write-Step "building debug pq-experiments"
    Build-ExperimentBinary -Release:$false
    $bin = Get-ExperimentBinary -Release:$false
    Invoke-Checked $bin @("list-proofs", "--results", $resultsDir, "--format", "text")

    $benchDirs = @()
    if (Test-Path -LiteralPath $resultsDir) {
        $benchDirs = @(Get-ChildItem -LiteralPath $resultsDir -Directory -Filter "bench-*" | Sort-Object Name)
    }
    if ($benchDirs.Count -eq 0) {
        throw "no bench directories found under $resultsDir"
    }
    $defaultIndex = ""
    for ($index = 0; $index -lt $benchDirs.Count; $index++) {
        $proofDir = Join-Path $benchDirs[$index].FullName "proofs"
        $count = 0
        if (Test-Path -LiteralPath $proofDir) {
            $count = @(Get-ChildItem -LiteralPath $proofDir -File -Filter "*.proof.json").Count
        }
        if ($count -gt 0) {
            $defaultIndex = [string]($index + 1)
        }
    }
    if ($defaultIndex.Length -eq 0) {
        throw "bench directories were found, but none contain proofs under proofs\*.proof.json"
    }
    $selection = Read-Text -Prompt "benchmark number or directory to verify" -Default $defaultIndex
    $dir = ""
    $selectedNumber = 0
    if ([int]::TryParse($selection, [ref]$selectedNumber)) {
        if ($selectedNumber -lt 1 -or $selectedNumber -gt $benchDirs.Count) {
            throw "benchmark selection out of range"
        }
        $dir = $benchDirs[$selectedNumber - 1].FullName
    } else {
        $dir = $selection
    }
    if ($dir.Length -eq 0) {
        throw "no benchmark result directory selected"
    }
    $selectedProofDir = Join-Path $dir "proofs"
    if (-not (Test-Path -LiteralPath $selectedProofDir)) {
        throw "selected bench has no proofs directory: $dir"
    }
    Write-Host "Proofs in ${dir}:"
    Get-ChildItem -LiteralPath $selectedProofDir -File -Filter "*.proof.json" | ForEach-Object {
        Write-Host "  $($_.Name)"
    }
    $format = Read-Choice -Prompt "report format [json|csv]" -Default "json" -Allowed @("json", "csv")
    $proofChoice = Read-Text -Prompt "proof id/file to verify, or all" -Default "all"
    $args = @("verify-proof", $dir, "--format", $format)
    if ($proofChoice -eq "all") {
        $args += "--all"
    } else {
        $args += @("--proof", $proofChoice)
    }
    Invoke-Checked $bin $args
}

function Show-Menu {
    Write-Section "pq_dSNARK interactive entrypoint (PowerShell)"
    Write-Host "1. Environment setup/check"
    Write-Host "2. Proof experiment"
    Write-Host "3. Verify experiments"
    Write-Host "4. Performance benchmark"
    Write-Host "0. Exit"
}

function Invoke-Menu {
    while ($true) {
        Show-Menu
        $choice = Read-RequiredChoice -Prompt "Select an action 0|1|2|3|4" -Allowed @("0", "1", "2", "3", "4")
        switch ($choice) {
            "0" { return }
            "1" { Invoke-SetupWizard }
            "2" { Invoke-ProofWizard }
            "3" { Invoke-ResultsWizard }
            "4" { Invoke-BenchmarkWizard }
        }
    }
}

function Initialize-InteractiveScript {
    param([object[]]$PipelineInput)

    Set-StrictMode -Version 3.0
    $ErrorActionPreference = "Stop"

    $scriptRoot = if ($PSScriptRoot -and $PSScriptRoot.Length -gt 0) {
        $PSScriptRoot
    } else {
        Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    if (-not $scriptRoot -or $scriptRoot.Length -eq 0) {
        throw "could not determine script directory"
    }

    $Script:RepoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptRoot "..\..")).Path
    Set-Location -LiteralPath $Script:RepoRoot

    $Script:QueuedInput = [System.Collections.Generic.Queue[string]]::new()
    foreach ($item in $PipelineInput) {
        $Script:QueuedInput.Enqueue([string]$item)
    }
}

function Write-StartupFailureLog {
    param([string]$Message)

    try {
        $base = if ($Script:RepoRoot) { $Script:RepoRoot } else { (Get-Location).Path }
        $logDir = Join-Path $base "results\logs"
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
        $logPath = Join-Path $logDir "interactive-powershell-last.log"
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "[$timestamp] $Message" | Out-File -LiteralPath $logPath -Encoding UTF8 -Append
        Write-Host "Log: $logPath"
    } catch {
        Write-Host "Log write failed: $($_.Exception.Message)"
    }
}

function Pause-BeforeExit {
    if ($NoPause) {
        return
    }
    Write-Host ""
    try {
        Read-Host "Press Enter to exit" | Out-Null
    } catch {
        Write-Host "Press Enter to exit..."
        try {
            [Console]::In.ReadLine() | Out-Null
        } catch {
            Start-Sleep -Seconds 10
        }
    }
}

$exitCode = 0
try {
    Initialize-InteractiveScript -PipelineInput @($input)
    Invoke-Menu
} catch {
    $exitCode = 1
    Write-Host ""
    $message = "ERROR: $($_.Exception.Message)"
    Write-Host $message -ForegroundColor Red
    Write-StartupFailureLog -Message $message
} finally {
    Pause-BeforeExit
}
exit $exitCode
