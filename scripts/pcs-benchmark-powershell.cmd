@echo off
rem Launcher for the distributed-PCS comparison benchmark (Windows).
rem With arguments, forwards them to scripts\benchmark.py. With no arguments,
rem opens an interactive menu and pauses before exiting.
setlocal EnableExtensions
cd /d "%~dp0.."
where py >nul 2>nul
if %errorlevel%==0 (
  set "PY_CMD=py"
) else (
  set "PY_CMD=python"
)

if not "%~1"=="" (
  %PY_CMD% scripts\benchmark.py %*
  exit /b %errorlevel%
)

set "DEFAULT_ARGS=--out results/depcs-fourway-parallel-merkle-nv18-24-w2-w4 --fair-sequential --depcs-nv-range 18..24 --depcs-workers 2,4 --depcs-backends deepfold:2 --depcs-opening protocol11 --ligesis-nvs 18,19,20,21,22,23,24 --ligesis-parties-list 2,4 --external-pcs-schemes dfrittata-pcs,dpip-fri-pcs --pcs-queries 1 --repeats 1"

echo Code-based dePCS benchmark launcher (Windows)
echo.
echo 1^) Run default nv=18..24 workers=2,4 five-way benchmark
echo 2^) Dry-run default schedule
echo 3^) Enter custom benchmark.py arguments
echo 4^) Show benchmark.py help
echo 5^) Quit
echo.
set /p "CHOICE=Select [1-5]: "

if "%CHOICE%"=="1" (
  %PY_CMD% scripts\benchmark.py %DEFAULT_ARGS%
  set "BENCH_EXIT=%errorlevel%"
  goto done
)
if "%CHOICE%"=="2" (
  %PY_CMD% scripts\benchmark.py %DEFAULT_ARGS% --dry-run
  set "BENCH_EXIT=%errorlevel%"
  goto done
)
if "%CHOICE%"=="3" (
  echo Enter arguments exactly as you would pass after scripts\benchmark.py:
  set /p "CUSTOM_ARGS="
  %PY_CMD% scripts\benchmark.py %CUSTOM_ARGS%
  set "BENCH_EXIT=%errorlevel%"
  goto done
)
if "%CHOICE%"=="4" (
  %PY_CMD% scripts\benchmark.py --help
  set "BENCH_EXIT=%errorlevel%"
  goto done
)

echo Canceled.
set "BENCH_EXIT=0"

:done
echo.
pause
exit /b %BENCH_EXIT%
