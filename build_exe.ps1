# Compila LDWinPy a un unico .exe con manifiesto de Administrador.
# Uso:  powershell -ExecutionPolicy Bypass -File build_exe.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Instalando dependencias de build..." -ForegroundColor Cyan
python -m pip install --quiet --upgrade scapy pyinstaller

Write-Host "Compilando LDWin.exe (requiere admin, con GUI)..." -ForegroundColor Cyan
pyinstaller --noconfirm --clean --onefile --windowed `
    --name LDWin `
    --uac-admin `
    --collect-submodules scapy `
    --hidden-import ldwin.gui `
    run_gui.py

Write-Host ""
Write-Host "Listo. Binario en: dist\LDWin.exe" -ForegroundColor Green
Write-Host "Nota: pktmon ya viene en Windows; no se empaqueta nada de captura." -ForegroundColor DarkGray
