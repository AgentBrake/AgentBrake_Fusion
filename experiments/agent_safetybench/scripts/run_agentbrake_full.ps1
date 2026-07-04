param(
  [string]$Model = "deepseek-v4-flash",
  [string]$BaseUrl = "https://api.deepseek.com/v1",
  [string]$ApiKeyEnv = "DEEPSEEK_API_KEY",
  [int]$Limit = 2000,
  [int]$Workers = 8,
  [int]$MaxRounds = 10,
  [switch]$Responder,
  [switch]$Resume
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $Root

$SafeModel = $Model -replace "[^A-Za-z0-9_.-]", "_"
$Defenses = @("none", "ab_strict", "ab_gateway", "ab_oracle")
if ($Responder) {
  $Defenses = @("none", "ab_strict_responder", "ab_gateway_responder", "ab_oracle_responder")
}

foreach ($Defense in $Defenses) {
  $OutDir = "experiments\agent_safetybench\reports\$SafeModel\$Defense"
  $Args = @(
    "experiments\agent_safetybench\agentbrake_runner.py",
    "--model", $Model,
    "--api-key-env", $ApiKeyEnv,
    "--base-url", $BaseUrl,
    "--defense", $Defense,
    "--limit", "$Limit",
    "--workers", "$Workers",
    "--max-rounds", "$MaxRounds",
    "--timeout", "180",
    "--out-dir", $OutDir
  )
  if ($Resume) {
    $Args += "--resume"
  }
  Write-Host "Running $Model / $Defense -> $OutDir"
  python @Args
}
