"""Small configurable policy override layer."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from .models import ActionIR, Decision, PolicyDecision

VALID_DECISIONS: set[str] = {"allow", "allow_in_sandbox", "require_confirmation", "sandbox_then_approval", "block", "quarantine"}
DECISION_RANK = {"allow": 0, "allow_in_sandbox": 1, "require_confirmation": 2, "sandbox_then_approval": 3, "quarantine": 4, "block": 5}


class ConfigurablePolicyOverrides:
    """Apply simple YAML/JSON policy overrides after core PolicyEngine.

    Supported shape:
      rules:
        - name: block_ci
          match: {semantic_action: modify_ci_pipeline}
          decision: block
          reason: configured_block_ci
    """

    def __init__(self, rules: list[dict[str, Any]] | None = None):
        self.rules = rules or []
        self._events: list[dict[str, Any]] = []

    @classmethod
    def from_file(cls, path: str | Path | None) -> "ConfigurablePolicyOverrides":
        if not path:
            return cls()
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(p)
        text = p.read_text(encoding="utf-8")
        if p.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            try:
                import yaml  # type: ignore

                data = yaml.safe_load(text) or {}
            except ImportError as exc:
                raise RuntimeError("PyYAML is required for YAML policy config; install agentbrake[yaml] or use JSON") from exc
        return cls(list((data or {}).get("rules", [])))

    def apply(self, action: ActionIR, decision: PolicyDecision) -> PolicyDecision:
        self._events = []
        for rule in self.rules:
            if not self._matches(rule.get("match", {}), action, decision):
                continue
            new_decision = str(rule.get("decision") or decision.decision)
            reason = str(rule.get("reason") or rule.get("name") or "configured_policy_override")
            if new_decision not in VALID_DECISIONS:
                self._events.append(
                    {
                        "event": "invalid_policy_override_decision",
                        "rule": rule.get("name"),
                        "requested_decision": new_decision,
                        "kept_decision": decision.decision,
                    }
                )
                return replace(
                    decision,
                    reason_codes=list(dict.fromkeys([*decision.reason_codes, "invalid_policy_override_decision"])),
                )
            if self._is_invariant_protected(decision) and self._is_unsafe_downgrade(decision.decision, new_decision):
                self._events.append(
                    {"event": "unsafe_policy_downgrade_rejected", "rule": rule.get("name"), "from": decision.decision, "to": new_decision}
                )
                self._events.append(
                    {
                        "event": "invariant_policy_downgrade_rejected",
                        "rule": rule.get("name"),
                        "from": decision.decision,
                        "to": new_decision,
                    }
                )
                return replace(
                    decision,
                    reason_codes=list(
                        dict.fromkeys(
                            [*decision.reason_codes, "unsafe_policy_downgrade_rejected", "invariant_policy_downgrade_rejected", reason]
                        )
                    ),
                )
            if self._is_unsafe_downgrade(decision.decision, new_decision) and not self._has_trusted_unsafe_override(rule):
                self._events.append(
                    {"event": "unsafe_policy_downgrade_rejected", "rule": rule.get("name"), "from": decision.decision, "to": new_decision}
                )
                return replace(
                    decision,
                    reason_codes=list(dict.fromkeys([*decision.reason_codes, "unsafe_policy_downgrade_rejected", reason])),
                )
            risk_score = int(rule.get("risk_score") or decision.risk_score)
            controls = list(rule.get("required_controls") or decision.required_controls)
            return replace(
                decision,
                decision=new_decision,  # type: ignore[arg-type]
                risk_score=max(decision.risk_score, risk_score),
                reason_codes=list(dict.fromkeys([*decision.reason_codes, reason])),
                required_controls=list(dict.fromkeys(controls)),
                explanation=str(rule.get("explanation") or decision.explanation),
            )
        return decision

    def consume_events(self) -> list[dict[str, Any]]:
        events = self._events
        self._events = []
        return events

    @staticmethod
    def _is_unsafe_downgrade(current: Decision, requested: str) -> bool:
        if current in {"block", "quarantine", "sandbox_then_approval", "require_confirmation"}:
            return DECISION_RANK[requested] < DECISION_RANK[current]
        if current == "allow_in_sandbox" and requested == "allow":
            return True
        return False

    @staticmethod
    def _has_trusted_unsafe_override(rule: dict[str, Any]) -> bool:
        return bool(rule.get("unsafe_override") and (rule.get("trusted_admin_policy") or rule.get("admin_signed")))

    @staticmethod
    def _is_invariant_protected(decision: PolicyDecision) -> bool:
        if any(bool(rule.get("invariant")) for rule in decision.matched_rules):
            return True
        for trace in decision.rule_trace:
            hits = trace.get("invariant_hits") if isinstance(trace, dict) else None
            if hits:
                return True
        return False

    @staticmethod
    def _matches(match: dict[str, Any], action: ActionIR, decision: PolicyDecision) -> bool:
        if not match:
            return False
        if match.get("semantic_action") and match["semantic_action"] != action.semantic_action:
            return False
        if match.get("tool") and str(match["tool"]).lower() != action.tool.lower():
            return False
        if match.get("risk") and match["risk"] != action.risk:
            return False
        if match.get("decision") and match["decision"] != decision.decision:
            return False
        tag = match.get("risk_tag")
        if tag and tag not in action.risk_tags:
            return False
        return True
