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
call :steps > "%LOG%" 2>&1
type "%LOG%"
echo.
echo Xong. Ket qua da luu tai %LOG%
pause
exit /b

:steps
echo [uninstall]
.venv\Scripts\python.exe -m sentinel service uninstall
if exist "%SNAPSHOT%" rmdir /s /q "%SNAPSHOT%"
echo [snapshot]
.venv\Scripts\python.exe -m sentinel service snapshot --source "%SNAPSHOT%"
if errorlevel 1 exit /b 1
echo [install]
.venv\Scripts\python.exe -m sentinel service install --source "%SNAPSHOT%"
if errorlevel 1 exit /b 1
echo [verify]
.venv\Scripts\python.exe -m sentinel service verify --restart
exit /b
