param(
  [int]$Workers = 12,
  [string]$BaseUrl = "https://api.deepseek.com/v1",
  [string]$ApiKeyEnv = "DEEPSEEK_API_KEY",
  [string]$Model = "deepseek-v4-flash"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $Root

python "experiments\agent_safetybench\progent_runner.py" `
  --model $Model `
  --api-key-env $ApiKeyEnv `
  --base-url $BaseUrl `
  --policy-model $Model `
  --policy-api-key-env $ApiKeyEnv `
  --policy-base-url $BaseUrl `
  --out-dir "experiments\agent_safetybench\reports\progent_deepseek_v4_flash_official_rerun_v1" `
  --limit 2000 `
  --workers $Workers `
  --timeout 180 `
  --max-rounds 10 `
  --resume
