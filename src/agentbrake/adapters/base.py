"""Adapter protocol for external agents.

A real Codex/Cline/OpenHands/aider adapter only needs to convert each planned
agent tool call into guard_action(...), then honour AgentBrake-Fusion's decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(slots=True)
class AgentToolCall:
    raw_action: str
    tool: str = "Bash"
    source_ids: list[str] | None = None
    operation: str | None = None
    file_path: str | None = None


class CodingAgentAdapter(Protocol):
    def next_actions(self) -> list[AgentToolCall]: ...

    def apply_allowed_action(self, call: AgentToolCall) -> None: ...
