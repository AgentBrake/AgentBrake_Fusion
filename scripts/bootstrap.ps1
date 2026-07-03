param(
  [string]$Python = "python",
  [string]$Node = "node"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

& $Python --version
& $Node --version

if (-not (Test-Path ".venv")) {
  & $Python -m venv .venv
}

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
  $VenvPython = $Python
}

& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r backend/requirements.txt
& $VenvPython -m pip install -e ".[test]"

if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env" }
if (-not (Test-Path "backend\.env")) { Copy-Item "backend\.env.example" "backend\.env" }
if (-not (Test-Path "web\studio\.env")) { Copy-Item "web\studio\.env.example" "web\studio\.env" }

New-Item -ItemType Directory -Force -Path data\scenarios,data\agentdojo_results,data\sample_traces,artifacts\logs,artifacts\reports,artifacts\screenshots,artifacts\figures,artifacts\videos | Out-Null

Push-Location web\studio
npm install
Pop-Location

Write-Host ""
Write-Host "Bootstrap complete."
Write-Host "Next:"
Write-Host "  powershell -ExecutionPolicy Bypass -File scripts/run_all.ps1"
Write-Host "  powershell -ExecutionPolicy Bypass -File scripts/run_demo.ps1"
Write-Host "  powershell -ExecutionPolicy Bypass -File scripts/run_tests.ps1"
