param(
  [int]$Workers = 6,
  [string]$BaseUrl = "https://dashscope.aliyuncs.com/compatible-mode/v1",
  [string]$ApiKeyEnv = "DASHSCOPE_API_KEY"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $Root

$Common = @(
  "experiments\agent_safetybench\progent_runner.py",
  "--api-key-env", $ApiKeyEnv,
  "--base-url", $BaseUrl,
  "--policy-api-key-env", $ApiKeyEnv,
  "--policy-base-url", $BaseUrl,
  "--limit", "2000",
  "--workers", "$Workers",
  "--timeout", "180",
  "--max-rounds", "10",
  "--resume"
)

python @Common --model deepseek-v4-flash --policy-model deepseek-v4-flash --out-dir "experiments\agent_safetybench\reports\progent_deepseek_v4_flash_rerun_v1"
python @Common --model qwen-plus --policy-model qwen-plus --out-dir "experiments\agent_safetybench\reports\progent_qwen_plus_rerun_v1"
