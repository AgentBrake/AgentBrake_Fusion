"""Evidence-indexed candidate retrieval for MSJ Engine rules."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .fact_normalizer import FactNormalizer
from .fact_registry import fact_spec
from .facts import PolicyFactSet
from .rule_schema import CompiledPolicyRule, IndexHint


@dataclass(slots=True)
class RetrievalTrace:
    total_rules: int
    candidate_rules: int = 0
    residual_rules: int = 0
    global_rules: int = 0
    pruned_rules: int = 0
    candidate_reduction_ratio: float = 1.0
    postings: list[dict[str, Any]] = field(default_factory=list)
    composite_hits: list[dict[str, Any]] = field(default_factory=list)
    pruned: list[dict[str, Any]] = field(default_factory=list)
    indexed_fact_keys: list[str] = field(default_factory=list)
    candidate_rule_ids: list[str] = field(default_factory=list)
    safe_prune_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rules": self.total_rules,
            "candidate_rules": self.candidate_rules,
            "residual_rules": self.residual_rules,
            "global_rules": self.global_rules,
            "pruned_rules": self.pruned_rules,
            "candidate_reduction_ratio": self.candidate_reduction_ratio,
            "postings": self.postings,
            "composite_hits": self.composite_hits,
            "pruned": self.pruned,
            "indexed_fact_keys": self.indexed_fact_keys,
            "candidate_rule_ids": self.candidate_rule_ids,
            "safe_prune_enabled": self.safe_prune_enabled,
        }


class EvidenceIndex:
    def __init__(self) -> None:
        self.exact: dict[str, set[str]] = defaultdict(set)
        self.presence: dict[str, set[str]] = defaultdict(set)
        self.range_buckets: dict[str, set[str]] = defaultdict(set)
        self.composite: dict[tuple[str, ...], set[str]] = defaultdict(set)
        self.residual_rules: set[str] = set()
        self.global_rules: set[str] = set()

    def add_hint(self, rule_id: str, hint: IndexHint) -> None:
        if not hint.expected_values:
            self.presence[hint.path].add(rule_id)
            return
        for value in hint.expected_values:
            token = f"{hint.path}={value}"
            if hint.strategy == "presence":
                self.presence[hint.path].add(rule_id)
            elif hint.strategy == "range":
                self.range_buckets[token].add(rule_id)
            else:
                self.exact[token].add(rule_id)


class RuleIndex:
    def __init__(self, rules: list[CompiledPolicyRule], *, enable_safe_prune: bool = False):
        self.rules = rules
        self.by_id = {rule.rule_id: rule for rule in rules}
        self.normalizer = FactNormalizer()
        self.index = EvidenceIndex()
        self.rule_tokens: dict[str, set[str]] = {}
        self.enable_safe_prune = enable_safe_prune
        for rule in rules:
            tokens: set[str] = set()
            if not rule.index_hints:
                self.index.global_rules.add(rule.rule_id)
            for hint in rule.index_hints:
                if hint.group == "unless":
                    self.index.residual_rules.add(rule.rule_id)
                    continue
                self.index.add_hint(rule.rule_id, hint)
                tokens.update(f"{hint.path}={value}" for value in hint.expected_values if value)
            if _has_residual(rule):
                self.index.residual_rules.add(rule.rule_id)
            if not tokens and rule.rule_id not in self.index.residual_rules:
                self.index.global_rules.add(rule.rule_id)
            self.rule_tokens[rule.rule_id] = tokens
        self._build_composites()

    def candidates(self, facts: PolicyFactSet) -> tuple[list[CompiledPolicyRule], dict[str, Any]]:
        keys = self.normalizer.keys_for_fact_set(facts)
        tokens = {key.token() for key in keys}
        trace = RetrievalTrace(
            total_rules=len(self.rules),
            residual_rules=len(self.index.residual_rules),
            global_rules=len(self.index.global_rules),
            indexed_fact_keys=sorted(tokens),
            safe_prune_enabled=self.enable_safe_prune,
        )
        selected: set[str] = set(self.index.global_rules) | set(self.index.residual_rules)
        counts_by_dimension: dict[str, int] = defaultdict(int)

        for key in sorted(keys, key=lambda k: k.token()):
            before = len(selected)
            posting_ids = set(self.index.exact.get(key.token(), set()))
            posting_ids |= set(self.index.presence.get(key.path, set()))
            posting_ids |= set(self.index.range_buckets.get(key.token(), set()))
            selected |= posting_ids
            delta = len(selected) - before
            counts_by_dimension[_dimension_name(key.path)] += delta
            if posting_ids:
                trace.postings.append({"key": key.token(), "rules": len(posting_ids), "rule_ids": sorted(posting_ids)})

        for composite, rule_ids in self.index.composite.items():
            if set(composite) <= tokens:
                selected |= rule_ids
                trace.composite_hits.append({"keys": list(composite), "rules": len(rule_ids), "rule_ids": sorted(rule_ids)})

        selected = self._safe_prune(selected, tokens, trace)
        candidates = [self.by_id[rule_id] for rule_id in sorted(selected) if rule_id in self.by_id]
        trace.candidate_rules = len(candidates)
        trace.candidate_rule_ids = [rule.rule_id for rule in candidates]
        trace.pruned_rules = len(trace.pruned)
        trace.candidate_reduction_ratio = round(len(candidates) / len(self.rules), 4) if self.rules else 0.0
        stats = {
            "total_rules": len(self.rules),
            "candidate_rules": len(candidates),
            "global_rules": len(self.index.global_rules),
            "residual_rules": len(self.index.residual_rules),
            "candidate_reduction_ratio": trace.candidate_reduction_ratio,
            "retrieval_trace": trace.to_dict(),
            **{name: counts_by_dimension.get(name, 0) for name in _LEGACY_DIMENSIONS},
        }
        return candidates, stats

    def _build_composites(self) -> None:
        valuable = {
            ("source.has_untrusted=true", "action.high_risk=true"),
            ("asset.touched_type=secret_file", "action.network_capability=true"),
            ("package.source=git_url", "source.has_untrusted=true"),
            ("package.source=tarball_url", "source.has_untrusted=true"),
            ("asset.touched_type=ci_workflow", "source.has_untrusted=true"),
            ("sandbox.risk_observed=package_lifecycle", "package.source=registry"),
            ("mcp.capability=auth", "source.has_untrusted=true"),
            ("flow.secret_to_external=true", "action.network_capability=true"),
            ("history.secret_taint=true", "action.network_capability=true"),
            ("graph.has_dataflow_edge=true", "asset.touched_type=secret_file"),
        }
        for rule_id, tokens in self.rule_tokens.items():
            for composite in valuable:
                if set(composite) <= tokens:
                    self.index.composite[tuple(sorted(composite))].add(rule_id)

    def _safe_prune(self, candidates: set[str], fact_tokens: set[str], trace: RetrievalTrace) -> set[str]:
        if not self.enable_safe_prune:
            return candidates

        tokens_by_path: dict[str, set[str]] = defaultdict(set)
        for token in fact_tokens:
            path, sep, value = token.partition("=")
            if sep:
                tokens_by_path[path].add(value)

        kept: set[str] = set()
        for rule_id in candidates:
            rule = self.by_id.get(rule_id)
            signature = rule.signature if rule else None
            if not rule or not signature or signature.has_unless or signature.residual_predicates or signature.any_groups:
                kept.add(rule_id)
                continue

            impossible = self._first_impossible_must_key(signature.must_keys, tokens_by_path)
            if impossible is None:
                kept.add(rule_id)
                continue
            trace.pruned.append(
                {
                    "rule_id": rule_id,
                    "path": impossible["path"],
                    "expected": sorted(impossible["expected"]),
                    "actual": sorted(impossible["actual"]),
                    "reason": "single-valued fact has no overlap with rule's required value",
                }
            )
        return kept

    @staticmethod
    def _first_impossible_must_key(must_keys: set[str], tokens_by_path: dict[str, set[str]]) -> dict[str, Any] | None:
        required_by_path: dict[str, set[str]] = defaultdict(set)
        for token in must_keys:
            path, sep, value = token.partition("=")
            if sep and value:
                required_by_path[path].add(value)

        for path, expected in sorted(required_by_path.items()):
            spec = fact_spec(path)
            if spec is None or not spec.monotone_safe or spec.value_type == "list" or spec.index_strategy == "list_each":
                continue
            actual = tokens_by_path.get(path, set())
            if actual and expected.isdisjoint(actual):
                return {"path": path, "expected": expected, "actual": actual}
        return None


def _has_residual(rule: CompiledPolicyRule) -> bool:
    ops = {str(pred.get("operator")) for pred in rule.predicates}
    return bool(ops & {"regex", "not_exists"}) or bool(rule.unless)


_LEGACY_DIMENSIONS = {
    "by_action_semantic",
    "by_action_risk",
    "by_source_trust",
    "by_asset_type",
    "by_package_source",
    "by_secret_event",
    "by_contract_match",
    "by_mcp_capability",
    "by_sandbox_observation",
}


def _dimension_name(path: str) -> str:
    return {
        "action.semantic_action": "by_action_semantic",
        "action.risk": "by_action_risk",
        "source.trust_floor": "by_source_trust",
        "source.has_untrusted": "by_source_trust",
        "asset.touched_type": "by_asset_type",
        "package.source": "by_package_source",
        "secret.event": "by_secret_event",
        "contract.match": "by_contract_match",
        "mcp.capability": "by_mcp_capability",
        "sandbox.risk_observed": "by_sandbox_observation",
    }.get(path, "by_action_risk")
