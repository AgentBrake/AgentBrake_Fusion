"""Generate AgentBrake-Fusion agent integration scaffolding."""

from __future__ import annotations

import json
from pathlib import Path

SHIM_NAMES = ["npm", "git", "curl", "python"]


def init_agent(
    repo: str | Path, agentbrake_home: str | Path, agent: str = "generic", task: str = "general agent task", force: bool = False
) -> dict:
    repo_path = Path(repo).resolve()
    root = repo_path / ".agentbrake"
    shims = root / "shims"
    root.mkdir(parents=True, exist_ok=True)
    shims.mkdir(parents=True, exist_ok=True)

    config = {
        "agent": agent,
        "repo": str(repo_path),
        "agentbrake_home": str(Path(agentbrake_home).resolve()),
        "task": task,
        "gateway_base_url": "http://127.0.0.1:8765/v1",
        "api_key": "agentbrake-fusion-local",
    }
    _write(root / "config.json", json.dumps(config, ensure_ascii=False, indent=2) + "\n", force)
    _write(root / "agent-instructions.md", _instructions(config), force)
    for name in SHIM_NAMES:
        _write(shims / name, _posix_shim(name), force)
        _write(shims / f"{name}.ps1", _powershell_shim(name), force)
    return {"config": str(root / "config.json"), "instructions": str(root / "agent-instructions.md"), "shims": str(shims), "agent": agent}


def _write(path: Path, text: str, force: bool) -> None:
    if path.exists() and not force:
        return
    path.write_text(text, encoding="utf-8")


def _instructions(config: dict) -> str:
    return f"""# AgentBrake-Fusion agent instructions

Use AgentBrake-Fusion for model and shell execution.

Model API:

```text
base_url = {config["gateway_base_url"]}
api_key  = {config["api_key"]}
```

Shell commands:

```bash
PYTHONPATH={config["agentbrake_home"]}/src python -m agentbrake exec-guard --repo {config["repo"]} --task "{config["task"]}" -- <command>
```

If PATH shims are enabled, put `{config["repo"]}/.agentbrake/shims` first in PATH.
"""


def _posix_shim(name: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
REAL_CMD="$(command -v {name}.real || true)"
if [ -z "$REAL_CMD" ]; then
  REAL_CMD="/usr/bin/{name}"
fi
PYTHONPATH="${{AGENTBRAKE_HOME}}/src" python -m agentbrake exec-guard \\
  --repo "${{AGENTBRAKE_REPO:-$PWD}}" \\
  --task "${{AGENTBRAKE_TASK:-general agent task}}" \\
  -- "$REAL_CMD" "$@"
"""


def _powershell_shim(name: str) -> str:
    return f"""$repo = if ($env:AGENTBRAKE_REPO) {{ $env:AGENTBRAKE_REPO }} else {{ (Get-Location).Path }}
$task = if ($env:AGENTBRAKE_TASK) {{ $env:AGENTBRAKE_TASK }} else {{ "general agent task" }}
$rs = if ($env:AGENTBRAKE_HOME) {{ $env:AGENTBRAKE_HOME }} else {{ (Resolve-Path ".").Path }}
$env:PYTHONPATH = Join-Path $rs "src"
python -m agentbrake exec-guard --repo $repo --task $task -- {name} @args
exit $LASTEXITCODE
"""
