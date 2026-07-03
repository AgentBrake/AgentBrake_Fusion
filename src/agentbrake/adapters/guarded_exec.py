"""Guarded command adapter for real agent shell-tool integration."""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..control_plane import AgentBrakeControlPlane
from ..gateway.openai_compat import _redact_secret_text
from ..models import sha256_text


@dataclass(slots=True)
class GuardedExecResult:
    command: str
    decision: dict
    action: dict
    executed: bool = False
    sandboxed: bool = False
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    audit_log: str | None = None
    notes: list[str] = field(default_factory=list)


class GuardedExecAdapter:
    """Wrap a real shell command with AgentBrake-Fusion pre-execution checks.

    Agents that can customize their shell tool can run:
      AgentBrake-Fusion exec-guard --repo <repo> --task <task> -- <command...>
    """

    def __init__(self, repo_root: str | Path, control_plane: AgentBrakeControlPlane, task: str):
        self.repo_root = Path(repo_root).resolve()
        self.cp = control_plane
        self.task = task

    def run(self, command: list[str], source_ids: list[str] | None = None) -> GuardedExecResult:
        if self.cp.contract is None:
            self.cp.build_contract(self.task)
        raw_action = shlex.join(command)
        action, decision = self.cp.guard_action(raw_action, source_ids=source_ids or [], tool="Bash")
        result = GuardedExecResult(
            command=raw_action,
            action=asdict(action),
            decision=asdict(decision),
            audit_log=str(self.cp.audit.log_path),
        )

        if decision.decision == "allow":
            self.cp.audit.append(
                "host_exec_started",
                {"command": raw_action},
                task_id=self.cp.contract.task_id if self.cp.contract else None,
                actor="guarded_exec_adapter",
                source_ids=action.source_ids,
                action_id=action.action_id,
                decision_id=decision.decision_id,
            )
            proc = subprocess.run(command, cwd=self.repo_root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            result.executed = True
            result.exit_code = proc.returncode
            result.stdout = proc.stdout
            result.stderr = proc.stderr
            self.cp.audit.append(
                "host_exec_completed",
                {
                    "command": raw_action,
                    "exit_code": proc.returncode,
                    "stdout_hash": sha256_text(proc.stdout or ""),
                    "stderr_hash": sha256_text(proc.stderr or ""),
                    "stdout_truncated_redacted": _redact_secret_text(proc.stdout)[:1200],
                    "stderr_truncated_redacted": _redact_secret_text(proc.stderr)[:1200],
                },
                task_id=self.cp.contract.task_id if self.cp.contract else None,
                actor="guarded_exec_adapter",
                source_ids=action.source_ids,
                action_id=action.action_id,
                decision_id=decision.decision_id,
            )
            return result

        if decision.decision == "allow_in_sandbox":
            trace = self.cp.sandbox.preflight(action, decision=decision)
            self.cp.audit.append(
                "exec_trace",
                asdict(trace),
                task_id=self.cp.contract.task_id if self.cp.contract else None,
                actor="guarded_exec_adapter",
                action_id=action.action_id,
            )
            result.sandboxed = True
            result.exit_code = trace.exit_code
            result.notes.append("allowed_in_sandbox: command was preflighted instead of executed on host")
            return result

        if decision.decision in {"require_confirmation", "sandbox_then_approval"}:
            result.notes.append("approval_required: command was not executed")
            return result

        result.notes.append("blocked: command was not executed")
        return result
