"""Studio Pro read-model dataclasses."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class StudioEvent:
    schema_version: str
    event_id: str
    timestamp: str
    run_id: str
    session_id: str
    request_id: str
    span_id: str
    parent_span_id: str | None
    event_index: int
    type: str
    phase: str
    severity: str
    summary: str
    agent_name: str = "unknown"
    demo_scenario_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    redaction: dict[str, Any] = field(default_factory=lambda: {"applied": True, "fields": ["payload"]})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RunSummary:
    run_id: str
    session_id: str
    started_at: str
    updated_at: str
    event_count: int = 0
    blocked_count: int = 0
    approval_count: int = 0
    action_count: int = 0
    critical_count: int = 0
    latest_decision: str = ""
    agent_name: str = "unknown"
    demo_scenario_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ActionDetail:
    action_id: str
    run_id: str
    action: dict[str, Any] = field(default_factory=dict)
    decision: dict[str, Any] = field(default_factory=dict)
    runtime: dict[str, Any] = field(default_factory=dict)
    instruction: dict[str, Any] = field(default_factory=dict)
    sources: list[dict[str, Any]] = field(default_factory=list)
    evidence_events: list[dict[str, Any]] = field(default_factory=list)
    action_graph: dict[str, Any] = field(default_factory=dict)
    session_state: dict[str, Any] = field(default_factory=dict)
    policy_fact_set: dict[str, Any] = field(default_factory=dict)
    policy_eval_trace: dict[str, Any] = field(default_factory=dict)
    policy_predicates: list[dict[str, Any]] = field(default_factory=list)
    policy_lattice_path: list[dict[str, Any]] = field(default_factory=list)
    policy_causal_graph: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScenarioSpec:
    id: str
    name: str
    kind: str
    description: str
    source_type: str
    attack_body: str
    expected_decision: str
    dangerous_action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
