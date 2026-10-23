# test:202 — one-command local start (Windows PowerShell)
#   powershell -ExecutionPolicy Bypass -File .\start.ps1
# Creates the Python environment and builds the web client on first run, then
# serves everything at http://localhost:5000 and opens the browser.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$py = ".\.venv-win\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Host "Creating Python environment..."
    py -3 -m venv .venv-win
    & $py -m pip install --quiet --upgrade pip
    & $py -m pip install --quiet -r requirements.txt
}

if (-not (Test-Path ".\client\ui\dist\index.html")) {
    Write-Host "Building the web client..."
    Push-Location .\client\ui
    npm install --silent
    npm run build
    Pop-Location
}

$env:ABE_MODE = if ($env:ABE_MODE) { $env:ABE_MODE } else { "simulated" }
Start-Job { Start-Sleep 2; Start-Process "http://localhost:5000" } | Out-Null
& $py -m server.app
