from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REPORT_DIR = ROOT / "experiments" / "agentdojo" / "reports" / "runs"
LOG_DIR = ROOT / "experiments" / "agentdojo" / "logs"

DEFENSE_LOG_DIRS = {
    "none": "no_defense",
    "tool_filter": "tool_filter",
    "gateway_only": "gateway_only_fast",
    "agentdojo_firewall": "agentdojo_firewall_fair",
}


def ensure_dirs() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def run_eval(*, suite: str, defense: str, run_name: str, attack: str, model: str | None = None) -> None:
    ensure_dirs()
    defense_name = "gateway_only" if defense in {"agentbrake_toolgate", "gateway_only_fast"} else defense
    log_name = DEFENSE_LOG_DIRS.get(defense_name, run_name)
    log_dir = LOG_DIR / log_name
    if log_dir.exists():
        import datetime

        log_dir = LOG_DIR / f"{log_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if defense_name == "gateway_only":
        cmd = [
            sys.executable,
            "-m",
            "agentbrake.eval.agentdojo.runner.run_tool_firewall_eval",
            "--suite",
            suite,
            "--model",
            model or os.getenv("MODEL", "deepseek-chat"),
            "--defense",
            "agentbrake_toolgate",
            "--attack",
            attack,
            "--run-name",
            run_name,
            "--logdir",
            str(log_dir),
            "--report-dir",
            str(REPORT_DIR),
        ]
    else:
        cmd = [
            sys.executable,
            "-m",
            "agentbrake.eval.agentdojo.runner.run_benchmark",
            "--suite",
            suite,
            "--model",
            model or os.getenv("MODEL", "deepseek-chat"),
            "--defense",
            defense_name,
            "--attack",
            attack,
            "--out-dir",
            str(log_dir),
        ]
    subprocess.run(cmd, check=True, cwd=str(ROOT))



