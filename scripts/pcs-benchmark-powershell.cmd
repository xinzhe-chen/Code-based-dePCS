@echo off
setlocal EnableExtensions
cd /d "%~dp0.."

:menu
echo Distributed Brakedown PCS benchmark
echo 1^) Run PCS benchmark
echo 0^) Exit
set "choice=0"
set /p "choice=Select: "
if "%choice%"=="0" exit /b 0
if not "%choice%"=="1" (
  echo Unknown option: %choice%
  goto menu
)

set "runner="
set "opening=compact"
set "n_min=8"
set "n_max=10"
set "worker_min=0"
set "worker_max=2"
set "pcs_queries=1"

set /p "runner=runner local^|network^|both: "
if not "%runner%"=="local" if not "%runner%"=="network" if not "%runner%"=="both" (
  echo expected one of: local network both
  goto menu
)
set /p "opening=opening compact^|full^|both [compact]: "
if "%opening%"=="" set "opening=compact"
if not "%opening%"=="compact" if not "%opening%"=="full" if not "%opening%"=="both" (
  echo expected one of: compact full both
  goto menu
)
set /p "n_min=minimum PCS size exponent n for N=2^n: "
if "%n_min%"=="" set "n_min=8"
set /p "n_max=maximum PCS size exponent n for N=2^n: "
if "%n_max%"=="" set "n_max=10"
if %n_min% GTR %n_max% (
  echo minimum PCS size exponent must be ^<= maximum PCS size exponent
  goto menu
)
set /p "worker_min=minimum worker exponent for workers=2^w: "
if "%worker_min%"=="" set "worker_min=0"
set /p "worker_max=maximum worker exponent for workers=2^w: "
if "%worker_max%"=="" set "worker_max=2"
if %worker_min% GTR %worker_max% (
  echo minimum worker exponent must be ^<= maximum worker exponent
  goto menu
)
if %worker_max% GTR %n_min% (
  echo maximum worker exponent must be ^<= minimum PCS size exponent n
  echo for n_min=%n_min%, use maximum worker exponent ^<= %n_min% or increase n_min
  goto menu
)
set /p "pcs_queries=PCS queries: "
if "%pcs_queries%"=="" set "pcs_queries=1"

cargo run -p pq-experiments -- pcs-benchmark --runner "%runner%" --opening "%opening%" --n-range "%n_min%..%n_max%" --worker-power-range "%worker_min%..%worker_max%" --pcs-queries "%pcs_queries%"
goto menu
