param(
  [string]$RepoUrl = "https://github.com/thu-coai/Agent-SafetyBench.git",
  [string]$Commit = "74feea8de601b3a1449a93fcf70017fe61556f73"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$Upstream = Join-Path $Root "experiments\agent_safetybench\upstream"

if (-not (Test-Path $Upstream)) {
  git clone $RepoUrl $Upstream
}

Push-Location $Upstream
try {
  git fetch origin
  git checkout $Commit
  if (Test-Path "requirements.txt") {
    python -m pip install -r requirements.txt
  }
}
finally {
  Pop-Location
}

Write-Host "Agent-SafetyBench upstream is ready at $Upstream"
Write-Host "Pinned commit: $Commit"
