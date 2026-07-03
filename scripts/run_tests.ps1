$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root
$env:PYTHONPATH = "$Root\src;$env:PYTHONPATH"

python -m pytest -q tests/test_studio_pro.py
Push-Location web\studio
npm run build
Pop-Location
python scripts/healthcheck.py --ensure-backend --ci
