<#
.SYNOPSIS
    Gera dist\FirawynixMonitor.exe com PyInstaller.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build.ps1
    powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -PythonVersion 3.13 -SkipTests
#>
param(
    [string]$PythonVersion = "3.12",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$venvPython = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "==> Criando ambiente virtual (.venv) com Python $PythonVersion"
    & py "-$PythonVersion" -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Python $PythonVersion não encontrado (instale via python.org ou winget)." }
}

Write-Host "==> Instalando dependências congeladas"
& $venvPython -m pip install --upgrade pip | Out-Null
& $venvPython -m pip install -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw "Falha ao instalar dependências." }

if (-not $SkipTests) {
    Write-Host "==> Executando testes"
    & $venvPython -m pytest
    if ($LASTEXITCODE -ne 0) { throw "Testes falharam; build abortado." }
}

Write-Host "==> Empacotando com PyInstaller"
& $venvPython -m PyInstaller --noconfirm --clean FirawynixMonitor.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller falhou." }

Copy-Item servers.example.json dist\ -Force
Copy-Item .env.example dist\ -Force
Write-Host ""
Write-Host "OK: dist\FirawynixMonitor.exe"
Write-Host "Próximo passo: copie dist\servers.example.json para dist\servers.json e configure seus servidores."
