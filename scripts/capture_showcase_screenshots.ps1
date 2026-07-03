$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root
node scripts/capture_showcase_screenshots.mjs
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}
