@echo off
REM Lanzador de LDWinPy que se auto-eleva a Administrador (necesario para pktmon).
setlocal
cd /d "%~dp0"

REM Comprobar privilegios de administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando privilegios de Administrador...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

REM Ya somos admin: lanzar la GUI
python -m ldwin --gui
endlocal
