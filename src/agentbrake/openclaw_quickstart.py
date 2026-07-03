"""Generate a portable OpenClaw -> AgentBrake-Fusion setup."""

from __future__ import annotations

import json
from pathlib import Path


def generate_openclaw_quickstart(
    repo: str | Path,
    agentbrake_home: str | Path,
    *,
    model: str = "gpt-4.1",
    host: str = "127.0.0.1",
    port: int = 8765,
    upstream_base_url: str = "https://api.openai.com/v1",
    force: bool = False,
) -> dict[str, str]:
    repo_path = Path(repo).resolve()
    home_path = Path(agentbrake_home).resolve()
    root = repo_path / ".agentbrake" / "openclaw"
    root.mkdir(parents=True, exist_ok=True)

    ps1 = root / "start-AgentBrake-Fusion-openclaw.ps1"
    cmd = root / "start-AgentBrake-Fusion-openclaw.cmd"
    sh = root / "start-AgentBrake-Fusion-openclaw.sh"
    env_example = root / ".env.example"
    provider = root / "openclaw-provider.json"
    readme = root / "README.md"

    _write(
        ps1,
        _powershell_start_script(
            repo_path,
            home_path,
            model=model,
            host=host,
            port=port,
            upstream_base_url=upstream_base_url,
        ),
        force,
    )
    _write(cmd, _cmd_start_script(ps1), force)
    _write(
        sh,
        _posix_start_script(
            repo_path,
            home_path,
            model=model,
            host=host,
            port=port,
            upstream_base_url=upstream_base_url,
        ),
        force,
    )
    _write(env_example, _env_example(repo_path, home_path, model=model, host=host, port=port, upstream_base_url=upstream_base_url), force)
    _write(provider, json.dumps(_provider_config(model=model, host=host, port=port), ensure_ascii=False, indent=2) + "\n", force)
    _write(readme, _quickstart_readme(model=model, host=host, port=port, upstream_base_url=upstream_base_url), force)
    return {
        "start_powershell": str(ps1),
        "start_cmd": str(cmd),
        "start_posix": str(sh),
        "env_example": str(env_example),
        "provider_config": str(provider),
        "readme": str(readme),
        "base_url": f"http://{host}:{port}/v1",
        "api_key": "agentbrake-fusion-local",
        "model": model,
    }


def _write(path: Path, text: str, force: bool) -> None:
    if path.exists() and not force:
        return
    path.write_text(text, encoding="utf-8")


def _powershell_start_script(repo: Path, agentbrake_home: Path, *, model: str, host: str, port: int, upstream_base_url: str) -> str:
    return f"""$ErrorActionPreference = "Stop"

$repo = if ($env:AGENTBRAKE_REPO) {{ $env:AGENTBRAKE_REPO }} else {{ "{repo}" }}
$agentbrakeHome = if ($env:AGENTBRAKE_HOME) {{ $env:AGENTBRAKE_HOME }} else {{ "{agentbrake_home}" }}
$hostName = if ($env:AGENTBRAKE_HOST) {{ $env:AGENTBRAKE_HOST }} else {{ "{host}" }}
$portNumber = if ($env:AGENTBRAKE_PORT) {{ $env:AGENTBRAKE_PORT }} else {{ "{port}" }}
$upstreamBaseUrl = if ($env:AGENTBRAKE_UPSTREAM_BASE_URL) {{ $env:AGENTBRAKE_UPSTREAM_BASE_URL }} else {{ "{upstream_base_url}" }}
$modelName = if ($env:AGENTBRAKE_MODEL) {{ $env:AGENTBRAKE_MODEL }} else {{ "{model}" }}

if (-not $env:OPENAI_API_KEY) {{
  $env:OPENAI_API_KEY = Read-Host "Paste your upstream OpenAI API key"
}}

if (Test-Path (Join-Path $agentbrakeHome "src")) {{
  $env:PYTHONPATH = Join-Path $agentbrakeHome "src"
}}

Write-Host "Starting AgentBrake-Fusion for OpenClaw..."
Write-Host "OpenClaw Base URL: http://$hostName`:$portNumber/v1"
Write-Host "OpenClaw API Key:  agentbrake-fusion-local"
Write-Host "OpenClaw Model:    $modelName"

python -m agentbrake gateway-start `
  --repo "$repo" `
  --host "$hostName" `
  --port "$portNumber" `
  --upstream-base-url "$upstreamBaseUrl"
"""


def _cmd_start_script(ps1: Path) -> str:
    return f"""@echo off
powershell -ExecutionPolicy Bypass -File "{ps1}"
"""


def _posix_start_script(repo: Path, agentbrake_home: Path, *, model: str, host: str, port: int, upstream_base_url: str) -> str:
    return f"""#!/usr/bin/env sh
set -eu

AGENTBRAKE_REPO="${{AGENTBRAKE_REPO:-{repo.as_posix()}}}"
AGENTBRAKE_HOME="${{AGENTBRAKE_HOME:-{agentbrake_home.as_posix()}}}"
AGENTBRAKE_HOST="${{AGENTBRAKE_HOST:-{host}}}"
AGENTBRAKE_PORT="${{AGENTBRAKE_PORT:-{port}}}"
AGENTBRAKE_UPSTREAM_BASE_URL="${{AGENTBRAKE_UPSTREAM_BASE_URL:-{upstream_base_url}}}"
AGENTBRAKE_MODEL="${{AGENTBRAKE_MODEL:-{model}}}"

if [ -z "${{OPENAI_API_KEY:-}}" ]; then
  printf "Paste your upstream OpenAI API key: "
  stty -echo 2>/dev/null || true
  read OPENAI_API_KEY
  stty echo 2>/dev/null || true
  printf "\\n"
  export OPENAI_API_KEY
fi

if [ -d "$AGENTBRAKE_HOME/src" ]; then
  export PYTHONPATH="$AGENTBRAKE_HOME/src${{PYTHONPATH:+:$PYTHONPATH}}"
fi

printf "Starting AgentBrake-Fusion for OpenClaw...\\n"
printf "OpenClaw Base URL: http://%s:%s/v1\\n" "$AGENTBRAKE_HOST" "$AGENTBRAKE_PORT"
printf "OpenClaw API Key:  agentbrake-fusion-local\\n"
printf "OpenClaw Model:    %s\\n" "$AGENTBRAKE_MODEL"

python -m agentbrake gateway-start \\
  --repo "$AGENTBRAKE_REPO" \\
  --host "$AGENTBRAKE_HOST" \\
  --port "$AGENTBRAKE_PORT" \\
  --upstream-base-url "$AGENTBRAKE_UPSTREAM_BASE_URL"
"""


def _env_example(repo: Path, agentbrake_home: Path, *, model: str, host: str, port: int, upstream_base_url: str) -> str:
    return f"""# Copy to .env or export these variables before starting the script.
OPENAI_API_KEY=sk-your-upstream-key
AGENTBRAKE_REPO={repo}
AGENTBRAKE_HOME={agentbrake_home}
AGENTBRAKE_HOST={host}
AGENTBRAKE_PORT={port}
AGENTBRAKE_MODEL={model}
AGENTBRAKE_UPSTREAM_BASE_URL={upstream_base_url}

# LongCat example:
# OPENAI_API_KEY=ak-your-longcat-key
# AGENTBRAKE_MODEL=LongCat-Flash-Chat
# AGENTBRAKE_UPSTREAM_BASE_URL=https://api.longcat.chat/openai
"""


def _provider_config(*, model: str, host: str, port: int) -> dict:
    return {
        "models": {
            "mode": "merge",
            "providers": {
                "AgentBrake-Fusion": {
                    "baseUrl": f"http://{host}:{port}/v1",
                    "apiKey": "agentbrake-fusion-local",
                    "api": "openai-completions",
                    "models": [
                        {
                            "id": model,
                            "name": f"{model} via AgentBrake-Fusion",
                            "reasoning": False,
                            "input": ["text"],
                            "contextWindow": 128000,
                            "maxTokens": 32000,
                        }
                    ],
                }
            },
        }
    }


def _quickstart_readme(*, model: str, host: str, port: int, upstream_base_url: str) -> str:
    return f"""# OpenClaw + AgentBrake-Fusion Quickstart

Run one of these scripts from this directory:

```text
Windows PowerShell: ./start-AgentBrake-Fusion-openclaw.ps1
Windows CMD:        ./start-AgentBrake-Fusion-openclaw.cmd
macOS/Linux:        sh ./start-AgentBrake-Fusion-openclaw.sh
```

Paste your real upstream API key when prompted, or set `OPENAI_API_KEY` before
starting the script.

Then add a custom OpenAI-compatible provider in OpenClaw:

```text
Base URL: http://{host}:{port}/v1
API Key:  agentbrake-fusion-local
Model:    {model}
```

The local OpenClaw provider should always point to agentbrake. The real upstream
is configured on the AgentBrake-Fusion Gateway side:

```text
AGENTBRAKE_UPSTREAM_BASE_URL={upstream_base_url}
```

For LongCat keys such as `ak_...`, use:

```text
AGENTBRAKE_UPSTREAM_BASE_URL=https://api.longcat.chat/openai
AGENTBRAKE_MODEL=LongCat-Flash-Chat
```

OpenClaw should only see the local AgentBrake-Fusion key. Keep the terminal running
while using OpenClaw.

All generated paths can be overridden with environment variables. See
`.env.example`.
"""
