"""Tiny MSJ Engine policy rule compiler."""

from __future__ import annotations

from typing import Any

from .fact_normalizer import canonical_expected_values
from .fact_registry import fact_spec
from .rule_schema import CompiledPolicyRule, IndexHint, RuleSignature

VALID_DECISIONS = {"allow", "allow_in_sandbox", "require_confirmation", "sandbox_then_approval", "quarantine", "block"}
VALID_OPERATORS = {"eq", "in", "exists", "not_exists", "contains", "regex", "gte", "lte"}


class PolicyRuleCompiler:
    def compile(self, raw_rules: list[dict[str, Any]]) -> list[CompiledPolicyRule]:
        rules: list[CompiledPolicyRule] = []
        for item in raw_rules:
            rule_id = str(item.get("rule_id") or item.get("id") or "")
            if not rule_id:
                raise ValueError("policy rule missing rule_id")
            decision = str(item.get("decision") or "sandbox_then_approval")
            if decision not in VALID_DECISIONS:
                raise ValueError(f"invalid decision for {rule_id}: {decision}")
            predicates = self._normalise_predicates(dict(item.get("match") or {}), list(item.get("predicates") or []), rule_id)
            unless = self._normalise_unless(item.get("unless"), rule_id)
            hints = [*self._index_hints(predicates, unless), *self._explicit_index_hints(item.get("index_hints"), rule_id)]
            signature = self._signature(rule_id, str(item.get("category") or "domain"), hints, predicates, unless)
            rules.append(
                CompiledPolicyRule(
                    rule_id=rule_id,
                    name=str(item.get("name") or rule_id),
                    category=str(item.get("category") or "domain"),
                    match=dict(item.get("match") or {}),
                    decision=decision,  # type: ignore[arg-type]
                    risk_score=int(item.get("risk_score") or 70),
                    reason_codes=[str(r) for r in item.get("reason_codes", [])] or [rule_id.lower()],
                    predicates=predicates,
                    unless=unless,
                    required_controls=[str(c) for c in item.get("required_controls", [])],
                    index_hints=hints,
                    signature=signature,
                )
            )
        return rules

    def validate(self, raw_rules: list[dict[str, Any]]) -> list[str]:
        errors: list[str] = []
        try:
            self.compile(raw_rules)
        except ValueError as exc:
            errors.append(str(exc))
        return errors

    def _normalise_predicates(self, match: dict[str, Any], predicates: list[dict[str, Any]], rule_id: str) -> list[dict[str, Any]]:
        normalised: list[dict[str, Any]] = []
        for path, expected in match.items():
            if path in {"any", "all", "unless"}:
                continue
            op = "in" if path.endswith("_any") or isinstance(expected, list) else "eq"
            normalised.append({"path": self._path(path), "operator": op, "expected": expected, "index": True})
        for pred in predicates:
            if not isinstance(pred, dict):
                raise ValueError(f"{rule_id}: predicate must be an object")
            op = str(pred.get("operator") or "eq")
            if op not in VALID_OPERATORS:
                raise ValueError(f"{rule_id}: unsupported operator {op}")
            path = str(pred.get("path") or "")
            if not path:
                raise ValueError(f"{rule_id}: predicate.path is required")
            normalised.append(
                {"path": self._path(path), "operator": op, "expected": pred.get("expected"), "index": pred.get("index", True)}
            )
        for group in ("any", "all"):
            if group in match:
                items = match[group] if isinstance(match[group], list) else [match[group]]
                children = []
                for item in items:
                    if not isinstance(item, dict):
                        raise ValueError(f"{rule_id}: {group} predicate entries must be objects")
                    children.extend(self._normalise_predicates(item, [], rule_id))
                normalised.append({"operator": group, "predicates": children, "path": group, "expected": None})
        return normalised

    def _normalise_unless(self, unless: Any, rule_id: str) -> list[dict[str, Any]]:
        if not unless:
            return []
        items = unless if isinstance(unless, list) else [unless]
        normalised: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"{rule_id}: unless entries must be objects")
            normalised.extend(self._normalise_predicates(item, [], rule_id))
        return normalised

    @staticmethod
    def _path(path: str) -> str:
        namespace, _, key = path.partition(".")
        key = key.removesuffix("_any")
        if namespace == "action" and key == "semantic":
            key = "semantic_action"
        return f"{namespace}.{key}"

    def _index_hints(self, predicates: list[dict[str, Any]], unless: list[dict[str, Any]]) -> list[IndexHint]:
        hints: list[IndexHint] = []
        for pred in predicates:
            hints.extend(self._hint_for_predicate(pred, group="must"))
        for pred in unless:
            hints.extend(self._hint_for_predicate(pred, group="unless"))
        return hints

    @staticmethod
    def _explicit_index_hints(raw_hints: Any, rule_id: str) -> list[IndexHint]:
        if not raw_hints:
            return []
        if not isinstance(raw_hints, list):
            raise ValueError(f"{rule_id}: index_hints must be a list")
        hints: list[IndexHint] = []
        for idx, raw in enumerate(raw_hints):
            if not isinstance(raw, dict):
                raise ValueError(f"{rule_id}: index_hints[{idx}] must be an object")
            path = str(raw.get("path") or "")
            if fact_spec(path) is None:
                raise ValueError(f"{rule_id}: index_hints[{idx}].path is not a registered fact key")
            expected_raw = raw.get("expected_values", raw.get("expected"))
            expected_values = canonical_expected_values(expected_raw)
            hints.append(
                IndexHint(
                    path=path,
                    operator=str(raw.get("operator") or "eq"),
                    expected_values=expected_values,
                    group=str(raw.get("group") or "must"),
                    strategy=str(raw.get("strategy") or "exact"),
                )
            )
        return hints

    def _hint_for_predicate(self, pred: dict[str, Any], *, group: str) -> list[IndexHint]:
        op = str(pred.get("operator") or "")
        if op in {"any", "all"}:
            child_group = "any" if op == "any" else group
            hints: list[IndexHint] = []
            for child in pred.get("predicates", []) or []:
                hints.extend(self._hint_for_predicate(child, group=child_group))
            return hints
        if pred.get("index") is False:
            return []
        path = str(pred.get("path") or "")
        spec = fact_spec(path)
        if spec is None:
            return []
        if op in {"eq", "in", "exists", "gte", "lte", "contains"}:
            expected = ["__exists__"] if op == "exists" else canonical_expected_values(pred.get("expected"))
            if op in {"gte", "lte"}:
                strategy = "range"
            elif op == "exists":
                strategy = "presence"
            elif spec.index_strategy == "list_each":
                strategy = "list_each"
            else:
                strategy = "exact"
            return [IndexHint(path=path, operator=op, expected_values=expected, group=group, strategy=strategy)]
        return []

    @staticmethod
    def _signature(
        rule_id: str, category: str, hints: list[IndexHint], predicates: list[dict[str, Any]], unless: list[dict[str, Any]]
    ) -> RuleSignature:
        signature = RuleSignature(rule_id=rule_id, has_unless=bool(unless), safety_category=category)
        for hint in hints:
            tokens = {f"{hint.path}={value}" for value in hint.expected_values if value}
            if hint.group == "must":
                signature.must_keys.update(tokens)
            elif hint.group == "any":
                signature.any_groups.append(tokens)
            elif hint.group == "unless":
                signature.residual_predicates.append({"path": hint.path, "operator": hint.operator})
        residual_ops = {"regex", "not_exists"}
        for pred in predicates:
            if pred.get("operator") in residual_ops:
                signature.residual_predicates.append(pred)
        return signature
