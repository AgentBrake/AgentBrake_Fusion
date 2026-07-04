param(
  [Parameter(Mandatory = $true)]
  [string]$GenRes,
  [string]$TargetName = "agentbrake_asb",
  [string]$ModelPath = "thu-coai/ShieldAgent",
  [int]$BatchSize = 4,
  [string]$LabelType = ""
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$Upstream = Join-Path $Root "experiments\agent_safetybench\upstream"
$ScoreDir = Join-Path $Upstream "score"

if (-not (Test-Path $ScoreDir)) {
  throw "Missing Agent-SafetyBench upstream checkout. Run experiments\agent_safetybench\scripts\prepare_upstream.ps1 first."
}

$ResolvedGenRes = Resolve-Path $GenRes
$InputDir = Join-Path (Split-Path $ResolvedGenRes -Parent) "shield_input"
New-Item -ItemType Directory -Force -Path $InputDir | Out-Null
Copy-Item -Force $ResolvedGenRes (Join-Path $InputDir "gen_res.json")

Push-Location $ScoreDir
try {
  python "eval_with_shield.py" `
    --model_path $ModelPath `
    --filepath $InputDir `
    --filename "gen_res.json" `
    --label_type $LabelType `
    --batch_size $BatchSize `
    --target_model_name $TargetName
}
finally {
  Pop-Location
}

Write-Host "ShieldAgent result directory:"
Write-Host (Join-Path $ScoreDir "shield_results\$TargetName")
