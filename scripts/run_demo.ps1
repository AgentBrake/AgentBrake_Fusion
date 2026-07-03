$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root
$env:PYTHONPATH = "$Root\src;$env:PYTHONPATH"
python scripts/healthcheck.py --ensure-backend --demo
