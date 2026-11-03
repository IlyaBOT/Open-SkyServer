@echo off
setlocal
if "%~1"=="" (
  powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Patch-Skype.ps1"
) else (
  powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Patch-Skype.ps1" -ClientPath "%~1"
)
if errorlevel 1 (
  echo Patching failed. See the message above.
  pause
  exit /b 1
)
echo Patching completed. Use the Skype Patched desktop shortcut.
pause
