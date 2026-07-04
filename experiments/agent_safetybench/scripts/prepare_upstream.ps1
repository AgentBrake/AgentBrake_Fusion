param(
  [string]$RepoUrl = "https://github.com/thu-coai/Agent-SafetyBench.git",
  [string]$Commit = "74feea8de601b3a1449a93fcf70017fe61556f73",
  [switch]$SkipPipInstall
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$Upstream = Join-Path $Root "experiments\agent_safetybench\upstream"
$DataFile = Join-Path $Upstream "data\released_data.json"
$EnvDir = Join-Path $Upstream "environments"
$ScoreScript = Join-Path $Upstream "score\eval_with_shield.py"

function Invoke-Checked {
  param(
    [string]$Exe,
    [string[]]$Args
  )
  & $Exe @Args
  if ($LASTEXITCODE -ne 0) {
    throw "$Exe $($Args -join ' ') failed with exit code $LASTEXITCODE"
  }
}

if (Test-Path (Join-Path $Upstream ".git")) {
  Push-Location $Upstream
  try {
    Invoke-Checked git @("fetch", "origin")
    Invoke-Checked git @("checkout", $Commit)
  }
  finally {
    Pop-Location
  }
}
elseif (Test-Path $Upstream) {
  if (-not ((Test-Path $DataFile) -and (Test-Path $EnvDir) -and (Test-Path $ScoreScript))) {
    throw "Found $Upstream, but it is neither a git checkout nor a complete vendored Agent-SafetyBench tree."
  }
  Write-Host "Using vendored Agent-SafetyBench tree at $Upstream"
}
else {
  Invoke-Checked git @("clone", $RepoUrl, $Upstream)
  Push-Location $Upstream
  try {
    Invoke-Checked git @("checkout", $Commit)
  }
  finally {
    Pop-Location
  }
}

if (-not ((Test-Path $DataFile) -and (Test-Path $EnvDir) -and (Test-Path $ScoreScript))) {
  throw "Agent-SafetyBench upstream is incomplete. Missing data, environments, or score/eval_with_shield.py."
}

if (-not $SkipPipInstall) {
  if (Test-Path "requirements.txt") {
    Push-Location $Upstream
    try {
      Invoke-Checked python @("-m", "pip", "install", "-r", "requirements.txt")
    }
    finally {
      Pop-Location
    }
  }
}

Write-Host "Agent-SafetyBench upstream is ready at $Upstream"
$DataHash = (Get-FileHash $DataFile -Algorithm SHA256).Hash
Write-Host "Expected external upstream commit: $Commit"
Write-Host "released_data.json SHA256: $DataHash"
