param(
  [string]$HostName = $env:AGENTBRAKE_HOST,
  [int]$BackendPort = $(if ($env:AGENTBRAKE_BACKEND_PORT) { [int]$env:AGENTBRAKE_BACKEND_PORT } else { 8765 }),
  [int]$FrontendPort = $(if ($env:AGENTBRAKE_FRONTEND_PORT) { [int]$env:AGENTBRAKE_FRONTEND_PORT } else { 5173 })
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root
$EnvFile = Join-Path $Root ".env"
if (Test-Path $EnvFile) {
  foreach ($rawLine in Get-Content $EnvFile) {
    $line = $rawLine.Trim()
    if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) { continue }
    $parts = $line.Split("=", 2)
    $key = $parts[0].Trim()
    $value = $parts[1]
    if ($key -and -not [Environment]::GetEnvironmentVariable($key, "Process")) {
      [Environment]::SetEnvironmentVariable($key, $value, "Process")
    }
  }
}
if ($env:AGENTBRAKE_BACKEND_PORT -and -not $PSBoundParameters.ContainsKey("BackendPort")) { $BackendPort = [int]$env:AGENTBRAKE_BACKEND_PORT }
if ($env:AGENTBRAKE_FRONTEND_PORT -and -not $PSBoundParameters.ContainsKey("FrontendPort")) { $FrontendPort = [int]$env:AGENTBRAKE_FRONTEND_PORT }
if ($env:AGENTBRAKE_HOST -and -not $PSBoundParameters.ContainsKey("HostName")) { $HostName = $env:AGENTBRAKE_HOST }
if (-not $HostName) { $HostName = "127.0.0.1" }

New-Item -ItemType Directory -Force -Path artifacts\logs,.agentbrake | Out-Null

$ApiKey = if ($env:AGENTBRAKE_STUDIO_API_KEY) { $env:AGENTBRAKE_STUDIO_API_KEY } else { "agentbrake-fusion-local" }
$env:AGENTBRAKE_STUDIO_API_KEY = $ApiKey
$env:AGENTBRAKE_SANDBOX = if ($env:AGENTBRAKE_SANDBOX) { $env:AGENTBRAKE_SANDBOX } else { "true" }
$env:ALLOW_REAL_TOOLS = if ($env:ALLOW_REAL_TOOLS) { $env:ALLOW_REAL_TOOLS } else { "false" }
$env:PYTHONPATH = "$Root\src;$env:PYTHONPATH"
$BackendUrl = "http://${HostName}:${BackendPort}"
$FrontendUrl = "http://${HostName}:${FrontendPort}/react.html"
$env:VITE_AGENTBRAKE_BACKEND_URL = $BackendUrl

if ($env:OPENCLAW_GATEWAY_URL) {
  try {
    Invoke-RestMethod -Uri (($env:OPENCLAW_GATEWAY_URL.TrimEnd("/")) + "/health") -TimeoutSec 2 | Out-Null
    Write-Host "OpenClaw Gateway available: $env:OPENCLAW_GATEWAY_URL"
  } catch {
    Write-Host "OpenClaw Gateway unavailable, switching to mock demo mode."
  }
} else {
  Write-Host "OPENCLAW_GATEWAY_URL not set; using mock demo mode."
}

$Backend = Start-Process -FilePath "python" -ArgumentList @("-m","agentbrake.cli","studio-server","--repo",".","--host",$HostName,"--port",$BackendPort,"--demo-mode") -WorkingDirectory $Root -RedirectStandardOutput "$Root\artifacts\logs\backend.log" -RedirectStandardError "$Root\artifacts\logs\backend.err.log" -WindowStyle Hidden -PassThru
$Frontend = Start-Process -FilePath "npm" -ArgumentList @("run","dev","--","--host",$HostName,"--port",$FrontendPort) -WorkingDirectory "$Root\web\studio" -RedirectStandardOutput "$Root\artifacts\logs\frontend.log" -RedirectStandardError "$Root\artifacts\logs\frontend.err.log" -WindowStyle Hidden -PassThru

try {
  Write-Host "Frontend: $FrontendUrl"
  Write-Host "Backend:  $BackendUrl"
  Write-Host "Health:   $BackendUrl/api/health"
  Write-Host "Sandbox:  $env:AGENTBRAKE_SANDBOX"
  Write-Host "Real tools allowed: $env:ALLOW_REAL_TOOLS"
  Write-Host "Logs: artifacts/logs/backend.log and artifacts/logs/frontend.log"
  Write-Host "Press Ctrl+C to stop."
  while (-not $Backend.HasExited -and -not $Frontend.HasExited) {
    Start-Sleep -Seconds 1
  }
} finally {
  if (-not $Frontend.HasExited) { Stop-Process -Id $Frontend.Id -Force }
  if (-not $Backend.HasExited) { Stop-Process -Id $Backend.Id -Force }
}
