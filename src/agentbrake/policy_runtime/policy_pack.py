"""Policy pack runtime and mode handling."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from ..models import PolicyDecision
from ..policy_engine.compiler import VALID_DECISIONS as VALID_MSJ_DECISIONS
from ..policy_engine.compiler import VALID_OPERATORS

PolicyMode = Literal["enforce", "observe_only", "warn", "disabled"]
VALID_POLICY_MODES: set[str] = {"enforce", "observe_only", "warn", "disabled"}
VALID_POLICY_DECISIONS: set[str] = {"allow", "allow_in_sandbox", "require_confirmation", "sandbox_then_approval", "block", "quarantine"}


@dataclass(slots=True)
class PolicyHit:
    policy_name: str
    mode: PolicyMode
    reason_codes: list[str]
    decision: str
    would_block: bool
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RuntimePolicyResult:
    effective_decision: str
    original_decision: str
    mode: PolicyMode
    hits: list[PolicyHit]
    warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PolicyRuntime:
    """Wrap the core PolicyEngine decision with enforce/observe/warn behavior."""

    def __init__(self, mode: PolicyMode = "enforce", role: str = "local_dev_strict", *, unsafe_allow_disabled: bool = False) -> None:
        if mode == "disabled" and not unsafe_allow_disabled:
            raise ValueError("policy disabled mode requires explicit unsafe_allow_disabled=True")
        self.mode = mode
        self.role = role
        self.unsafe_allow_disabled = unsafe_allow_disabled

    def apply(self, decision: PolicyDecision, policy_name: str = "CoreAgentBrakePolicy") -> RuntimePolicyResult:
        would_block = decision.decision in {"block", "quarantine", "require_confirmation", "sandbox_then_approval"}
        hit = PolicyHit(
            policy_name,
            self.mode,
            decision.reason_codes,
            decision.decision,
            would_block,
            {
                "risk_score": decision.risk_score,
                "policy_version": decision.policy_version,
                "unsafe_allow_disabled": self.unsafe_allow_disabled,
            },
        )
        if self.mode == "disabled":
            return RuntimePolicyResult("allow", decision.decision, self.mode, [hit], warning="policy disabled")
        if self.mode == "observe_only":
            return RuntimePolicyResult(
                "allow", decision.decision, self.mode, [hit], warning="observe_only:would_block" if would_block else None
            )
        if self.mode == "warn":
            effective = "allow_in_sandbox" if would_block else decision.decision
            return RuntimePolicyResult(
                effective, decision.decision, self.mode, [hit], warning="warning:policy_triggered" if would_block else None
            )
        return RuntimePolicyResult(decision.decision, decision.decision, self.mode, [hit])


def load_policy_pack(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised without yaml extra
        raise RuntimeError("PyYAML is required to load YAML policy packs") from exc
    return yaml.safe_load(text) or {}


def validate_policy_pack(data: dict[str, Any]) -> list[str]:
    """Validate the stable demo policy-pack schema used by CLI/API/Studio.

    This intentionally stays small and explicit. It is a productization guardrail
    for policy packs, not a full policy language.
    """
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["policy pack must be an object"]
    version = str(data.get("version", ""))
    if version.startswith(("agentbrake-fusion-msj", "AgentBrake-Fusion-msj", "agentbrake-policygraph", "AgentBrake-Fusion-policygraph")):
        return _validate_msj_rule_pack(data)
    if not data.get("name") or not isinstance(data.get("name"), str):
        errors.append("name is required and must be a string")
    mode = data.get("mode", "enforce")
    if mode not in VALID_POLICY_MODES:
        errors.append(f"mode must be one of {sorted(VALID_POLICY_MODES)}")
    policies = data.get("policies", [])
    if not isinstance(policies, list) or not all(isinstance(p, str) and p for p in policies):
        errors.append("policies must be a list of non-empty strings")
    rules = data.get("rules", [])
    if rules is None:
        rules = []
    if not isinstance(rules, list):
        errors.append("rules must be a list when present")
        return errors
    for idx, rule in enumerate(rules):
        prefix = f"rules[{idx}]"
        if not isinstance(rule, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if not rule.get("name"):
            errors.append(f"{prefix}.name is required")
        if not isinstance(rule.get("match", {}), dict):
            errors.append(f"{prefix}.match must be an object")
        decision = rule.get("decision")
        if decision and decision not in VALID_POLICY_DECISIONS:
            errors.append(f"{prefix}.decision must be one of {sorted(VALID_POLICY_DECISIONS)}")
        if rule.get("unsafe_override") and not (rule.get("trusted_admin_policy") or rule.get("admin_signed")):
            errors.append(f"{prefix}.unsafe_override requires trusted_admin_policy or admin_signed")
    return errors


def _validate_msj_rule_pack(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(data.get("name"), str) or not data.get("name"):
        errors.append("name is required and must be a string")
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        return ["rules must be a list"]
    for idx, rule in enumerate(rules):
        prefix = f"rules[{idx}]"
        if not isinstance(rule, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if not rule.get("rule_id"):
            errors.append(f"{prefix}.rule_id is required")
        if rule.get("decision") not in VALID_MSJ_DECISIONS:
            errors.append(f"{prefix}.decision must be one of {sorted(VALID_MSJ_DECISIONS)}")
        if not isinstance(rule.get("match", {}), dict):
            errors.append(f"{prefix}.match must be an object")
        for pidx, pred in enumerate(rule.get("predicates", []) or []):
            if not isinstance(pred, dict):
                errors.append(f"{prefix}.predicates[{pidx}] must be an object")
                continue
            if not pred.get("path"):
                errors.append(f"{prefix}.predicates[{pidx}].path is required")
            op = str(pred.get("operator") or "eq")
            if op not in VALID_OPERATORS:
                errors.append(f"{prefix}.predicates[{pidx}].operator must be one of {sorted(VALID_OPERATORS)}")
        for hidx, hint in enumerate(rule.get("index_hints", []) or []):
            if not isinstance(hint, dict):
                errors.append(f"{prefix}.index_hints[{hidx}] must be an object")
                continue
            if not hint.get("path"):
                errors.append(f"{prefix}.index_hints[{hidx}].path is required")
        unless = rule.get("unless", [])
        unless_items = unless if isinstance(unless, list) else [unless] if unless else []
        for uidx, item in enumerate(unless_items):
            if not isinstance(item, dict):
                errors.append(f"{prefix}.unless[{uidx}] must be an object")
    return errors
