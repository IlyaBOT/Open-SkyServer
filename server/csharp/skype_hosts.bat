@echo off
setlocal
if /I "%~1"=="on" goto enable
if /I "%~1"=="off" goto disable
echo Usage: %~nx0 on ^| off
echo Run as Administrator. Changes only the managed Skype block in hosts.
echo Direct-IP connections and Skype authentication keys are unaffected.
exit /b 2

:enable
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0skype55_hosts_on.ps1"
exit /b %errorlevel%

:disable
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0skype55_hosts_off.ps1"
exit /b %errorlevel%
