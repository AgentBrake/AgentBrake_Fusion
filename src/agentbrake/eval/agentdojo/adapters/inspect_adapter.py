"""Inspect-style AgentDojo adapter entrypoints."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..state_tracker import AgentDojoStateTracker


@dataclass
class AgentBrakeFusionAgentDojoTask:
    suite: str
    repo_root: str
    task_id: str | None = None
    injection_task_id: str | None = None
    metadata: dict[str, Any] = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}


def agentbrake_agentdojo(
    *, repo_root: str | Path, suite: str, task_id: str | None = None, injection_task_id: str | None = None
) -> dict[str, Any]:
    from ....control_plane import AgentBrakeControlPlane
    from ..tool_gate import AgentBrakeToolGate

    cp = AgentBrakeControlPlane(repo_root)
    gate = AgentBrakeToolGate(cp)
    tracker = AgentDojoStateTracker()
    return {
        "task": AgentBrakeFusionAgentDojoTask(suite=suite, repo_root=str(repo_root), task_id=task_id, injection_task_id=injection_task_id),
        "control_plane": cp,
        "tool_gate": gate,
        "state_tracker": tracker,
    }


