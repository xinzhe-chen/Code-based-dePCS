@echo off
rem Launcher for the distributed-PCS comparison benchmark (Windows).
rem Forwards all arguments to scripts\benchmark.py. Run with --help for options.
setlocal
cd /d "%~dp0.."
where py >nul 2>nul
if %errorlevel%==0 (
  py scripts\benchmark.py %*
) else (
  python scripts\benchmark.py %*
)
exit /b %errorlevel%
