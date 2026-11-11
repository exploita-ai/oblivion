@echo off
setlocal DisableDelayedExpansion
"%~dp0bin\oblivion.exe" runtime install-bundle "%~dp0."
set "OblivionSetupExit=%errorlevel%"
if not "%OblivionSetupExit%"=="0" pause
exit /b %OblivionSetupExit%
