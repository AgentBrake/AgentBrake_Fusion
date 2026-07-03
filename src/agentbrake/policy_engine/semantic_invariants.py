"""Versioned semantic invariant registry backed by typed facts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .constraint_lattice import DecisionConstraints, constraints_to_decision
from .facts import PolicyFact, PolicyFactSet
from .rule_schema import RuleHit

Predicate = Callable[[PolicyFactSet], bool]
EvidenceSelector = Callable[[PolicyFactSet], list[PolicyFact]]


@dataclass(slots=True)
class SemanticInvariantSpec:
    invariant_id: str
    name: str
    predicate_expr: str
    required_fact_keys: list[str]
    min_constraints: DecisionConstraints
    reason_codes: list[str]
    required_controls: list[str]
    risk_score: int = 95
    category: str = "semantic_invariant"
    non_downgradable: bool = True
    evidence_hint: list[str] = field(default_factory=list)
    version: str = "v1"


@dataclass(slots=True)
class RegisteredInvariant:
    spec: SemanticInvariantSpec
    predicate: Predicate
    evidence: EvidenceSelector


class SemanticInvariantRegistry:
    version = "semantic-invariants-v1"

    def __init__(self) -> None:
        from .agentdojo_invariants import agentdojo_invariants

        self._items = [*_default_invariants(), *agentdojo_invariants()]

    def evaluate(self, facts: PolicyFactSet) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for item in self._items:
            if not item.predicate(facts):
                continue
            evidence_facts = item.evidence(facts)
            hits.append(_hit(item.spec, evidence_facts))
        return hits

    def specs(self) -> list[SemanticInvariantSpec]:
        return [item.spec for item in self._items]


def _default_invariants() -> list[RegisteredInvariant]:
    return [
        RegisteredInvariant(
            SemanticInvariantSpec(
                "INV-SECRET-001",
                "secret_asset_touch",
                "asset.touched_type IN secret_assets OR contract.forbidden_file_touch",
                ["asset.touched_type", "contract.forbidden_file_touch"],
                DecisionConstraints(execution_env="none", network_scope="deny", data_scope="no_secret", audit_scope="full"),
                ["secret_asset_touched"],
                ["block", "redact", "no_egress"],
                100,
                "secret",
            ),
            lambda f: (
                f.any_value("asset", "touched_type", {"secret_file", "secret_env", "publish_config", "forbidden_file"})
                or any(x.value is True for x in f.find("contract", "forbidden_file_touch"))
            ),
            lambda f: f.find("asset", "touched_type") + f.find("contract", "forbidden_file_touch"),
        ),
        RegisteredInvariant(
            SemanticInvariantSpec(
                "INV-EGRESS-001",
                "confirmed_secret_to_external_sink",
                "flow.secret_to_network_reachable OR (secret.event OR history.confirmed_secret_taint) AND action.network_capability",
                ["flow.secret_to_network_reachable", "secret.event", "history.confirmed_secret_taint", "action.network_capability"],
                DecisionConstraints(execution_env="none", network_scope="deny", data_scope="no_secret", audit_scope="full"),
                ["secret_egress_attempt"],
                ["block", "no_egress"],
                100,
                "egress",
            ),
            lambda f: (
                _bool(f, "flow", "secret_to_network_reachable")
                or (
                    (_secret_event(f) or _bool(f, "history", "confirmed_secret_taint"))
                    and (_bool(f, "action", "network_capability") or _bool(f, "sandbox", "network_attempts"))
                )
            ),
            lambda f: (
                f.find("flow", "secret_to_network_reachable")
                + f.find("secret")
                + f.find("history", "confirmed_secret_taint")
                + f.find("action", "network_capability")
                + f.find("sandbox", "network_attempts")
            ),
        ),
        RegisteredInvariant(
            SemanticInvariantSpec(
                "INV-EGRESS-001B",
                "attempted_secret_to_external_sink",
                "flow.attempted_secret_to_network_reachable OR history.attempted_secret_taint AND action.network_capability",
                ["flow.attempted_secret_to_network_reachable", "history.attempted_secret_taint", "action.network_capability"],
                DecisionConstraints(
                    execution_env="sandbox",
                    network_scope="deny",
                    data_scope="no_secret",
                    human_gate="approval_required",
                    audit_scope="full",
                ),
                ["attempted_secret_egress_requires_governance"],
                ["sandbox_preflight", "no_egress", "human_approval"],
                88,
                "egress",
            ),
            lambda f: (
                _bool(f, "flow", "attempted_secret_to_network_reachable")
                or (
                    _bool(f, "history", "attempted_secret_taint")
                    and not _bool(f, "history", "confirmed_secret_taint")
                    and (_bool(f, "action", "network_capability") or _bool(f, "sandbox", "network_attempts"))
                )
            ),
            lambda f: (
                f.find("flow", "attempted_secret_to_network_reachable")
                + f.find("history", "attempted_secret_taint")
                + f.find("action", "network_capability")
                + f.find("sandbox", "network_attempts")
            ),
        ),
        RegisteredInvariant(
            SemanticInvariantSpec(
                "INV-SOURCE-001",
                "untrusted_authority",
                "source.has_untrusted AND action.high_risk AND contract.match IN {violation,unknown}",
                ["source.has_untrusted", "action.high_risk", "contract.match"],
                DecisionConstraints(execution_env="none", audit_scope="full"),
                ["untrusted_source_cannot_authorize_high_risk_action"],
                ["block"],
                95,
                "source_authority",
            ),
            lambda f: (
                _bool(f, "source", "has_untrusted")
                and _bool(f, "action", "high_risk")
                and f.any_value("contract", "match", {"violation", "unknown"})
            ),
            lambda f: f.find("source") + f.find("action", "high_risk") + f.find("contract", "match"),
        ),
        RegisteredInvariant(
            SemanticInvariantSpec(
                "INV-REPO-001",
                "repo_boundary_escape",
                "asset.repo_escape OR asset.symlink_escape",
                ["asset.repo_escape", "asset.symlink_escape"],
                DecisionConstraints(execution_env="none", audit_scope="full"),
                ["repo_escape_or_symlink_escape"],
                ["block"],
                100,
                "repo_boundary",
            ),
            lambda f: _bool(f, "asset", "repo_escape") or _bool(f, "asset", "symlink_escape"),
            lambda f: f.find("asset", "repo_escape") + f.find("asset", "symlink_escape"),
        ),
        RegisteredInvariant(
            SemanticInvariantSpec(
                "INV-CI-001",
                "untrusted_ci_modification",
                "asset.touched_type=ci_workflow AND source.has_untrusted",
                ["asset.touched_type", "source.has_untrusted"],
                DecisionConstraints(execution_env="none", human_gate="approval_required", audit_scope="full"),
                ["untrusted_source_cannot_modify_ci_asset"],
                ["block", "human_approval"],
                95,
                "ci",
            ),
            lambda f: f.any_value("asset", "touched_type", {"ci_workflow"}) and _bool(f, "source", "has_untrusted"),
            lambda f: f.find("asset", "touched_type") + f.find("source", "has_untrusted"),
        ),
        RegisteredInvariant(
            SemanticInvariantSpec(
                "INV-SC-001",
                "untrusted_remote_dependency",
                "package.source IN {git_url,tarball_url} AND source.has_untrusted",
                ["package.source", "source.has_untrusted"],
                DecisionConstraints(execution_env="none", network_scope="deny", audit_scope="full"),
                ["untrusted_source_cannot_authorize_remote_package"],
                ["block", "package_preflight"],
                95,
                "supply_chain",
            ),
            lambda f: f.any_value("package", "source", {"git_url", "tarball_url"}) and _bool(f, "source", "has_untrusted"),
            lambda f: f.find("package", "source") + f.find("source", "has_untrusted"),
        ),
        RegisteredInvariant(
            SemanticInvariantSpec(
                "INV-MCP-001",
                "destructive_mcp_capability",
                "mcp.decision=blocked OR destructive mcp capability",
                ["mcp.decision", "mcp.capability"],
                DecisionConstraints(execution_env="none", audit_scope="full"),
                ["destructive_or_blocked_mcp_tool"],
                ["mcp_proxy", "block"],
                92,
                "mcp",
            ),
            lambda f: (
                f.any_value("mcp", "decision", {"blocked"})
                or any(
                    str(x.value).lower() in {"invoke_destructive_mcp_tool", "deploy", "publish", "delete", "auth", "credential"}
                    for x in f.find("mcp", "capability")
                )
            ),
            lambda f: f.find("mcp"),
        ),
        RegisteredInvariant(
            SemanticInvariantSpec(
                "INV-MEM-001",
                "tainted_memory_authorization",
                "memory.authorization_denied AND action.high_risk",
                ["memory.authorization_denied", "action.high_risk"],
                DecisionConstraints(execution_env="none", audit_scope="full"),
                ["memory_authorization_denied_high_risk"],
                ["memory_taint_gate", "block"],
                92,
                "memory",
            ),
            lambda f: _bool(f, "memory", "authorization_denied") and _bool(f, "action", "high_risk"),
            lambda f: f.find("memory") + f.find("action", "high_risk"),
        ),
        RegisteredInvariant(
            SemanticInvariantSpec(
                "INV-PARSER-001",
                "low_confidence_side_effect",
                "action.parser_confidence<0.6 AND action.side_effect",
                ["action.parser_confidence", "action.side_effect"],
                DecisionConstraints(execution_env="sandbox", human_gate="approval_required", audit_scope="full"),
                ["parser_confidence_below_threshold"],
                ["sandbox_preflight", "human_approval"],
                82,
                "parser",
            ),
            lambda f: (
                any(isinstance(x.value, (int, float)) and x.value < 0.6 for x in f.find("action", "parser_confidence"))
                and _bool(f, "action", "side_effect")
            ),
            lambda f: f.find("action", "parser_confidence") + f.find("action", "side_effect"),
        ),
    ]


def _hit(spec: SemanticInvariantSpec, evidence_facts: list[PolicyFact]) -> RuleHit:
    refs = [ref for fact in evidence_facts for ref in fact.evidence_refs]
    predicates = [
        {
            "fact_id": fact.fact_id,
            "namespace": fact.namespace,
            "key": fact.key,
            "value": fact.value,
            "matched": True,
            "semantic_invariant": spec.invariant_id,
        }
        for fact in evidence_facts[:20]
    ]
    return RuleHit(
        rule_id=spec.invariant_id,
        name=spec.name,
        category=spec.category,
        decision=constraints_to_decision(spec.min_constraints),
        risk_score=spec.risk_score,
        reason_codes=spec.reason_codes,
        required_controls=spec.required_controls,
        evidence_refs=list(dict.fromkeys(refs)),
        invariant=True,
        predicates=predicates,
        constraints=spec.min_constraints.to_dict(),
    )


def _bool(facts: PolicyFactSet, namespace: str, key: str) -> bool:
    return any(f.value is True for f in facts.find(namespace, key))


def _secret_event(facts: PolicyFactSet) -> bool:
    return facts.any_value("secret", "event", {"egress_after_secret", "token_like_value_in_tool_args", "secret_read"}) or bool(
        facts.find("secret", "event")
    )
