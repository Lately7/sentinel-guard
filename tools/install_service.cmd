@echo off
rem Owner-only: the one elevated step. Asks Windows for approval, replaces the
rem service with this checkout and proves it. Quarantine and logs in ProgramData
rem are kept. The result lands in %TEMP%\sentinel-install.log for review.
setlocal
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)
chcp 65001 >nul
rem Redirected output would otherwise use the ANSI code page and fail on Vietnamese.
set "PYTHONUTF8=1"
cd /d "%~dp0.."
set "SNAPSHOT=%TEMP%\sentinel-snapshot"
set "LOG=%TEMP%\sentinel-install.log"
echo Dang cai dich vu, khoang 1 phut. Dung bam vao cua so nay.
call :steps > "%LOG%" 2>&1
type "%LOG%"
echo.
echo Xong. Ket qua da luu tai %LOG%
pause
exit /b

:steps
rem Snapshot first: if it fails, the running service is left as it was.
if exist "%SNAPSHOT%" rmdir /s /q "%SNAPSHOT%"
echo [snapshot]
.venv\Scripts\python.exe -m sentinel service snapshot --source "%SNAPSHOT%"
if errorlevel 1 exit /b 1
echo [uninstall]
.venv\Scripts\python.exe -m sentinel service uninstall
echo [install]
.venv\Scripts\python.exe -m sentinel service install --source "%SNAPSHOT%"
if errorlevel 1 goto servicelog
echo [verify]
.venv\Scripts\python.exe -m sentinel service verify --restart
:servicelog
rem Only an administrator can read this, so it is copied while one is here.
echo [service log]
powershell -NoProfile -Command "Get-Content -LiteralPath (Join-Path $env:ProgramData 'SentinelGuard\journal\service.log') -Tail 40"
exit /b
