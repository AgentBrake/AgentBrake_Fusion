"""Evaluation context for the MSJ Engine."""

from __future__ import annotations

from dataclasses import dataclass

from ..models import (
    ActionIR,
    ContextGraph,
    ExecTrace,
    PackageEvent,
    RepoAssetGraph,
    SecretTaintEvent,
    SessionState,
    TaskContract,
)


@dataclass(slots=True)
class PolicyEvalContext:
    contract: TaskContract
    action: ActionIR
    asset_graph: RepoAssetGraph
    context_graph: ContextGraph
    package_event: PackageEvent | None = None
    secret_event: SecretTaintEvent | None = None
    exec_trace: ExecTrace | None = None
    phase: str = "pre_decide"
    session_state: SessionState | None = None
