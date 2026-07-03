"""Shared ActionGraph parser types."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..models import ActionEdge, ActionIR, ActionNode, ExecTrace, PackageEvent, SessionState


@dataclass(slots=True)
class GraphBuildContext:
    action: ActionIR
    run_id: str
    repo_root: Path | None = None
    exec_trace: ExecTrace | None = None
    package_event: PackageEvent | None = None
    session_state: SessionState | None = None


@dataclass(slots=True)
class GraphFragment:
    nodes: list[ActionNode] = field(default_factory=list)
    edges: list[ActionEdge] = field(default_factory=list)
    confidence: float = 1.0
    complete: bool = True
    parser_name: str = "unknown"
    warnings: list[str] = field(default_factory=list)


class ActionGraphParser(Protocol):
    name: str

    def can_parse(self, ctx: GraphBuildContext) -> bool: ...

    def parse(self, ctx: GraphBuildContext) -> GraphFragment: ...
