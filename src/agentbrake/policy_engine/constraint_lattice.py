"""Constraint Product Lattice for AgentBrake-Fusion decisions."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from ..models import Decision

ExecutionEnv = Literal["host", "sandbox", "none"]
NetworkScope = Literal["allow", "allowlist", "deny"]
DataScope = Literal["raw", "redacted", "no_secret"]
HumanGate = Literal["none", "approval_required"]
PersistenceScope = Literal["persist", "no_persist"]
AuditScope = Literal["basic", "full"]


@dataclass(slots=True)
class DecisionConstraints:
    execution_env: ExecutionEnv = "host"
    network_scope: NetworkScope = "allow"
    data_scope: DataScope = "raw"
    human_gate: HumanGate = "none"
    persistence_scope: PersistenceScope = "persist"
    audit_scope: AuditScope = "basic"

    def join(self, other: "DecisionConstraints") -> "DecisionConstraints":
        return DecisionConstraints(
            execution_env=_max(self.execution_env, other.execution_env, ["host", "sandbox", "none"]),
            network_scope=_max(self.network_scope, other.network_scope, ["allow", "allowlist", "deny"]),
            data_scope=_max(self.data_scope, other.data_scope, ["raw", "redacted", "no_secret"]),
            human_gate=_max(self.human_gate, other.human_gate, ["none", "approval_required"]),
            persistence_scope=_max(self.persistence_scope, other.persistence_scope, ["persist", "no_persist"]),
            audit_scope=_max(self.audit_scope, other.audit_scope, ["basic", "full"]),
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def constraints_for_decision(decision: Decision | str, controls: list[str] | None = None) -> DecisionConstraints:
    controls = controls or []
    c = DecisionConstraints()
    if decision in {"block", "quarantine"} or "block" in controls:
        c.execution_env = "none"
    elif decision == "sandbox_then_approval":
        c.execution_env = "sandbox"
        c.human_gate = "approval_required"
    elif decision == "require_confirmation":
        c.human_gate = "approval_required"
    elif decision == "allow_in_sandbox" or any(control in controls for control in {"sandbox", "sandbox_preflight", "package_preflight"}):
        c.execution_env = "sandbox"
    if any(control in controls for control in {"no_egress", "network_off", "block"}):
        c.network_scope = "deny"
    elif "network_allowlist" in controls:
        c.network_scope = "allowlist"
    if any(control in controls for control in {"redact", "secret_mount_masked", "no_secret"}):
        c.data_scope = "no_secret" if "no_secret" in controls or "secret_mount_masked" in controls else "redacted"
    if any(control in controls for control in {"human_approval", "double_approval", "block_or_human_approval", "block_or_admin_approval"}):
        c.human_gate = "approval_required"
    if any(control in controls for control in {"dry_run_only", "ttl"}):
        c.persistence_scope = "no_persist"
    if decision in {"block", "quarantine", "require_confirmation", "sandbox_then_approval"} or controls:
        c.audit_scope = "full"
    return c


def constraints_to_decision(c: DecisionConstraints) -> Decision:
    if c.execution_env == "none":
        return "block"
    if c.human_gate == "approval_required":
        return "sandbox_then_approval" if c.execution_env == "sandbox" else "require_confirmation"
    if c.execution_env == "sandbox":
        return "allow_in_sandbox"
    return "allow"


def explain_constraints(c: DecisionConstraints) -> str:
    parts = []
    if c.execution_env == "none":
        parts.append("no execution")
    elif c.execution_env == "sandbox":
        parts.append("sandbox execution")
    else:
        parts.append("host execution")
    if c.network_scope == "deny":
        parts.append("no external network")
    elif c.network_scope == "allowlist":
        parts.append("network allowlist")
    if c.data_scope == "redacted":
        parts.append("redacted data")
    elif c.data_scope == "no_secret":
        parts.append("secret data denied")
    if c.human_gate == "approval_required":
        parts.append("approval required")
    if c.persistence_scope == "no_persist":
        parts.append("no persistence")
    if c.audit_scope == "full":
        parts.append("full audit")
    return ", ".join(parts)


def _max(left: str, right: str, order: list[str]) -> str:
    return left if order.index(left) >= order.index(right) else right
