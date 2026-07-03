"""Predicate evaluator for compiled MSJ Engine rules."""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any

from ..models import new_id
from .facts import PolicyFactSet
from .rule_schema import CompiledPolicyRule, PredicateTrace, RuleHit


class RuleEvaluator:
    def evaluate(self, rules: list[CompiledPolicyRule], facts: PolicyFactSet) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for rule in rules:
            matched, traces = self._evaluate_rule(rule, facts)
            unless_traces = [self._eval_predicate(pred, facts) for pred in rule.unless]
            unless_matched = any(trace.matched for trace in unless_traces)
            if matched and not unless_matched:
                refs = [ref for trace in traces for ref in trace.evidence_refs]
                hits.append(
                    RuleHit(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        category=rule.category,
                        decision=rule.decision,
                        risk_score=rule.risk_score,
                        reason_codes=rule.reason_codes,
                        required_controls=rule.required_controls,
                        evidence_refs=list(dict.fromkeys(refs)),
                        invariant=False,
                        predicates=[asdict(t) for t in [*traces, *unless_traces]],
                    )
                )
        return hits

    def _evaluate_rule(self, rule: CompiledPolicyRule, facts: PolicyFactSet) -> tuple[bool, list[PredicateTrace]]:
        traces = [self._eval_predicate(pred, facts) for pred in rule.predicates]
        return all(trace.matched for trace in traces), traces

    def _eval_predicate(self, pred: dict[str, Any], facts: PolicyFactSet) -> PredicateTrace:
        op = str(pred.get("operator") or "eq")
        if op in {"any", "all"}:
            children = [self._eval_predicate(child, facts) for child in pred.get("predicates", [])]
            matched = any(c.matched for c in children) if op == "any" else all(c.matched for c in children)
            return PredicateTrace(
                predicate_id=new_id("pred"),
                path=str(pred.get("path") or op),
                operator=op,
                expected=pred.get("expected"),
                actual=[c.actual for c in children],
                matched=matched,
                matched_fact_ids=[fid for c in children for fid in c.matched_fact_ids],
                evidence_refs=list(dict.fromkeys([ref for c in children for ref in c.evidence_refs])),
            )
        path = str(pred.get("path") or "")
        namespace, _, key = path.partition(".")
        related = facts.find(namespace, key)
        actual = [f.value for f in related]
        matched_facts = [f for f in related if self._value_matches(f.value, op, pred.get("expected"))]
        if op == "exists":
            matched = bool(related)
            matched_facts = related
        elif op == "not_exists":
            matched = not related
            matched_facts = []
        else:
            matched = bool(matched_facts)
        return PredicateTrace(
            predicate_id=new_id("pred"),
            path=path,
            operator=op,
            expected=pred.get("expected"),
            actual=actual,
            matched=matched,
            matched_fact_ids=[f.fact_id for f in matched_facts],
            evidence_refs=list(dict.fromkeys([ref for f in matched_facts for ref in f.evidence_refs])),
        )

    @staticmethod
    def _value_matches(value: Any, op: str, expected: Any) -> bool:
        values = value if isinstance(value, list) else [value]
        expected_values = expected if isinstance(expected, list) else [expected]
        if op == "eq":
            return any(v == expected for v in values)
        if op == "in":
            return any(v in expected_values for v in values)
        if op == "contains":
            return any(str(expected) in str(v) for v in values)
        if op == "regex":
            return any(re.search(str(expected), str(v)) for v in values)
        if op == "gte":
            return any(_num(v) >= _num(expected) for v in values)
        if op == "lte":
            return any(_num(v) <= _num(expected) for v in values)
        return False


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
