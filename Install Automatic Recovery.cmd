@echo off
setlocal
cd /d "%~dp0"

if exist "%~dp0ClaudeRestart.exe" (
    "%~dp0ClaudeRestart.exe" --install-automation --pause
    exit /b
)

if not exist "%~dp0claude_restart.py" goto :missing

where py.exe >nul 2>&1
if not errorlevel 1 (
    py.exe -3 "%~dp0claude_restart.py" --install-automation --pause
    exit /b
)

where python.exe >nul 2>&1
if not errorlevel 1 (
    python.exe "%~dp0claude_restart.py" --install-automation --pause
    exit /b
)

:missing
echo Neither ClaudeRestart.exe nor Python 3 with claude_restart.py was found next to this launcher.
echo Download the latest release ZIP from https://github.com/TranDenyDFW/claude-appx-restart/releases
pause
exit /b 1
