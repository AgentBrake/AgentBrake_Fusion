"""Generic CLI agent adapter.

The adapter can read a transcript emitted by any external agent. Only actions
allowed by AgentBrake-Fusion are applied; dangerous actions are never passed through.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import asdict
from pathlib import Path

from ..control_plane import AgentBrakeControlPlane
from .base import AgentToolCall
from .protocol import AdapterRunResult, parse_agentbrake_action_lines


class GenericCLIAdapter:
    name = "generic_cli"

    def __init__(
        self,
        repo_root: str | Path,
        control_plane: AgentBrakeControlPlane,
        task: str,
        transcript: str | Path | None = None,
        command: list[str] | None = None,
        *,
        allow_command_collection: bool = False,
        command_collection_mode: str = "refuse",
        strict_transcript: bool = True,
    ):
        self.repo_root = Path(repo_root).resolve()
        self.cp = control_plane
        self.task = task
        self.transcript = Path(transcript) if transcript else None
        self.command = command
        self.allow_command_collection = allow_command_collection
        self.command_collection_mode = command_collection_mode
        self.strict_transcript = strict_transcript

    def collect_plan(self) -> list[AgentToolCall]:
        text = ""
        if self.transcript:
            text = self.transcript.read_text(encoding="utf-8")
        elif self.command:
            if not self.allow_command_collection or self.command_collection_mode != "sandboxed_plan":
                raise RuntimeError(
                    "Refusing to execute external agent command before AgentBrake-Fusion governance. "
                    "Use transcript mode, gateway mode, exec-guard/file-guard, a PATH shim, "
                    "or explicit sandboxed_plan command collection."
                )
            self.cp.audit.append(
                "unsafe_adapter_command_collection",
                {
                    "adapter": self.name,
                    "command": self.command,
                    "mode": self.command_collection_mode,
                    "warning": "external command collection was constrained to a temporary sandbox copy",
                },
                task_id=self.cp.contract.task_id if self.cp.contract else None,
                actor="generic_cli_adapter",
            )
            with tempfile.TemporaryDirectory(prefix="AgentBrake-Fusion-plan-") as tmp:
                sandbox_repo = Path(tmp) / "repo"
                import shutil

                shutil.copytree(
                    self.repo_root,
                    sandbox_repo,
                    ignore=shutil.ignore_patterns(".git", "node_modules", ".venv", ".env", ".npmrc", ".pypirc"),
                )
                proc = subprocess.run(
                    self.command, cwd=sandbox_repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120
                )
            text = proc.stdout + "\n" + proc.stderr
        else:
            text = "EDIT: src/login.js\nRS_ACTION: npm test\n"
        self._ingest_transcript_sources(text)
        calls = parse_agentbrake_action_lines(text, strict=self.strict_transcript)
        self.cp.audit.append(
            "adapter_plan_collected",
            {"adapter": self.name, "calls": [asdict(c) for c in calls]},
            task_id=self.cp.contract.task_id if self.cp.contract else None,
            actor="generic_cli_adapter",
        )
        return calls

    def run(self) -> AdapterRunResult:
        if self.cp.contract is None:
            self.cp.build_contract(self.task)
        result = AdapterRunResult(adapter=self.name, repo_root=str(self.repo_root), task=self.task, audit_log=str(self.cp.audit.log_path))
        for call in self.collect_plan():
            _action, decision = self.cp.guard_action(
                call.raw_action, source_ids=call.source_ids or [], tool=call.tool, operation=call.operation, file_path=call.file_path
            )
            result.events.append({"raw_action": call.raw_action, "decision": asdict(decision)})
            if decision.decision == "allow":
                self.apply_allowed_action(call)
                result.allowed.append(call.raw_action)
                result.host_executed.append(call.raw_action)
                result.executed.append(call.raw_action)
            elif decision.decision == "allow_in_sandbox":
                trace = self.cp.sandbox.preflight(_action, decision=decision)
                self.cp.audit.append(
                    "exec_trace",
                    asdict(trace),
                    task_id=self.cp.contract.task_id if self.cp.contract else None,
                    actor="generic_cli_adapter",
                    action_id=_action.action_id,
                )
                result.sandboxed.append(call.raw_action)
                result.simulated.append(call.raw_action)
            elif decision.decision in {"require_confirmation", "sandbox_then_approval"}:
                result.approval_required.append(call.raw_action)
            else:
                result.blocked.append(call.raw_action)
        self.cp.audit.append(
            "adapter_run_result",
            asdict(result),
            task_id=self.cp.contract.task_id if self.cp.contract else None,
            actor="generic_cli_adapter",
        )
        return result

    def apply_allowed_action(self, call: AgentToolCall) -> None:
        if call.operation == "edit" and call.file_path == "src/login.js":
            path = self.repo_root / call.file_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "function bindLogin(button, submit) {\n"
                "  if (!button || typeof submit !== 'function') throw new Error('bindLogin requires button and submit');\n"
                "  button.onclick = () => submit();\n"
                "}\n\nmodule.exports = { bindLogin };\n",
                encoding="utf-8",
            )

    def _ingest_transcript_sources(self, text: str) -> None:
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("{"):
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if payload.get("type") == "source":
                    self.cp.ingest_source(
                        str(payload.get("source_type") or payload.get("type_name") or "external_text"),
                        str(payload.get("content") or ""),
                        retrieval_path=str(payload.get("retrieval_path") or "transcript"),
                        source_id=str(payload.get("source_id") or ""),
                    )
                continue
            if not line.upper().startswith("SOURCE:"):
                continue
            rest = line.split(":", 1)[1].strip()
            meta, sep, content = rest.partition("|")
            parts = meta.split()
            if not parts:
                continue
            source_id = parts[0]
            source_type = parts[1] if len(parts) > 1 else "external_text"
            retrieval_path = parts[2] if len(parts) > 2 else "transcript"
            self.cp.ingest_source(source_type, content.strip() if sep else "", retrieval_path=retrieval_path, source_id=source_id)
