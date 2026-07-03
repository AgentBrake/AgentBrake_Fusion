"""Constraint Product Lattice merge logic for multi-source judgments."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ..feature_flags import feature_enabled
from ..models import Decision, PolicyDecision
from .constraint_lattice import constraints_for_decision, constraints_to_decision, explain_constraints
from .rule_schema import RuleHit

DECISION_RANK: dict[Decision, int] = {
    "allow": 0,
    "allow_in_sandbox": 1,
    "require_confirmation": 2,
    "sandbox_then_approval": 3,
    "quarantine": 4,
    "block": 5,
}


class ConstraintProductLattice:
    def merge(self, baseline: PolicyDecision, hits: list[RuleHit]) -> tuple[PolicyDecision, list[dict[str, Any]]]:
        constraint_enabled = feature_enabled("AGENTBRAKE_ENABLE_CONSTRAINT_LATTICE", default=True)
        decision: Decision = baseline.decision
        constraints = constraints_for_decision(baseline.decision, baseline.required_controls)
        path: list[dict[str, Any]] = [
            {
                "from": None,
                "to": baseline.decision,
                "via": "msj_baseline",
                "rank": DECISION_RANK[baseline.decision],
                "constraints": constraints.to_dict(),
            }
        ]
        reasons = list(baseline.reason_codes)
        controls = list(baseline.required_controls)
        risk_score = baseline.risk_score

        for hit in hits:
            hit_constraints = constraints_for_decision(hit.decision, hit.required_controls)
            if constraint_enabled:
                constraints = constraints.join(hit_constraints)
            hit_rank = DECISION_RANK[hit.decision]
            cur_rank = DECISION_RANK[decision]
            accepted = hit_rank >= cur_rank
            if accepted:
                previous = decision
                decision = hit.decision
                path.append(
                    {
                        "from": previous,
                        "to": decision,
                        "via": hit.rule_id,
                        "rank": hit_rank,
                        "constraints": constraints.to_dict(),
                        "constraint_join": hit_constraints.to_dict(),
                    }
                )
            else:
                path.append(
                    {
                        "from": decision,
                        "to": decision,
                        "via": hit.rule_id,
                        "rank": cur_rank,
                        "skipped_lower_rank": hit.decision,
                        "constraints": constraints.to_dict(),
                        "constraint_join": hit_constraints.to_dict(),
                    }
                )
            reasons.extend(hit.reason_codes)
            controls.extend(hit.required_controls)
            risk_score = max(risk_score, hit.risk_score)

        mapped_decision = constraints_to_decision(constraints)
        if constraint_enabled and DECISION_RANK[mapped_decision] > DECISION_RANK[decision]:
            previous = decision
            decision = mapped_decision
            path.append(
                {
                    "from": previous,
                    "to": decision,
                    "via": "constraint_product_lattice",
                    "rank": DECISION_RANK[decision],
                    "constraints": constraints.to_dict(),
                }
            )
        matched = [*baseline.matched_rules, *[hit.to_matched_rule() for hit in hits]]
        refs = [*baseline.evidence_refs, *[ref for hit in hits for ref in hit.evidence_refs]]
        return replace(
            baseline,
            decision=decision,
            risk_score=min(risk_score, 100),
            reason_codes=list(dict.fromkeys(reasons)),
            required_controls=list(dict.fromkeys(controls)),
            matched_rules=matched,
            evidence_refs=list(dict.fromkeys(refs)),
            rule_trace=[
                *baseline.rule_trace,
                {"engine": "constraint_product_lattice", "constraints": constraints.to_dict(), "mapped_decision": decision},
            ],
            metadata={
                **baseline.metadata,
                "decision_constraints": constraints.to_dict(),
                "constraint_summary": explain_constraints(constraints),
            },
        ), path


class DecisionLattice(ConstraintProductLattice):
    """Backward-compatible alias for the external Constraint Product Lattice."""
