@echo off
rem Shared dispatcher for the launchers: runs ClaudeRestart.exe when it sits beside this
rem file, otherwise claude_restart.py with py -3 or python.exe. All arguments pass through.
rem The exit code is the tool's own result (the tool waits for its elevated run). Each
rem branch ends with "exit /b %ERRORLEVEL%" on its own line: a bare "exit /b" does not
rem propagate the code out of "cmd /c", and inside a parenthesised block %ERRORLEVEL%
rem would expand before the command ran.
setlocal
cd /d "%~dp0"

if exist "%~dp0ClaudeRestart.exe" goto :exe
if not exist "%~dp0claude_restart.py" goto :missing
where py.exe >nul 2>&1
if not errorlevel 1 goto :py
where python.exe >nul 2>&1
if not errorlevel 1 goto :python
goto :missing

:exe
"%~dp0ClaudeRestart.exe" %*
exit /b %ERRORLEVEL%

:py
py.exe -3 "%~dp0claude_restart.py" %*
exit /b %ERRORLEVEL%

:python
python.exe "%~dp0claude_restart.py" %*
exit /b %ERRORLEVEL%

:missing
echo Neither ClaudeRestart.exe nor Python 3 with claude_restart.py was found next to this launcher.
echo Download the latest release ZIP from https://github.com/TranDenyDFW/claude-appx-restart/releases
pause
exit /b 1
