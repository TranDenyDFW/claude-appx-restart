@echo off
call "%~dp0ClaudeRestart-launch.cmd" --remove-automation --pause
exit /b %ERRORLEVEL%
