"""Rule dataclasses shared by invariants and DSL rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import Decision, new_id


@dataclass(slots=True)
class PredicateTrace:
    predicate_id: str
    path: str
    operator: str
    expected: Any
    actual: list[Any]
    matched: bool
    matched_fact_ids: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RuleHit:
    rule_id: str
    name: str
    category: str
    decision: Decision
    risk_score: int
    reason_codes: list[str]
    required_controls: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    invariant: bool = False
    predicates: list[dict[str, Any] | PredicateTrace] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)
    hit_id: str = field(default_factory=lambda: new_id("rulehit"))

    def to_matched_rule(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "decision": self.decision,
            "risk_score": self.risk_score,
            "reason_codes": ",".join(self.reason_codes),
            "invariant": self.invariant,
            "hit_id": self.hit_id,
            "constraints": self.constraints,
        }


@dataclass(frozen=True, slots=True)
class IndexHint:
    path: str
    operator: str
    expected_values: list[str]
    group: str = "must"
    strategy: str = "exact"


@dataclass(slots=True)
class RuleSignature:
    rule_id: str
    must_keys: set[str] = field(default_factory=set)
    should_keys: set[str] = field(default_factory=set)
    any_groups: list[set[str]] = field(default_factory=list)
    residual_predicates: list[dict[str, Any]] = field(default_factory=list)
    has_unless: bool = False
    safety_category: str = "domain"


@dataclass(slots=True)
class CompiledPolicyRule:
    rule_id: str
    name: str
    category: str
    match: dict[str, Any]
    decision: Decision
    risk_score: int
    reason_codes: list[str]
    predicates: list[dict[str, Any]] = field(default_factory=list)
    unless: list[dict[str, Any]] = field(default_factory=list)
    required_controls: list[str] = field(default_factory=list)
    index_hints: list[IndexHint] = field(default_factory=list)
    signature: RuleSignature | None = None
