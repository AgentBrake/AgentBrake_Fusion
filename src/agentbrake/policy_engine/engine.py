"""MSJ Engine implementation for the outer AgentBrake-Fusion decision model."""

from __future__ import annotations

import os
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from ..contract import IntentMatcher
from ..models import (
    ActionIR,
    ContextGraph,
    ExecTrace,
    IntentDiff,
    PackageEvent,
    PolicyDecision,
    RepoAssetGraph,
    SecretTaintEvent,
    SessionState,
    TaskContract,
    new_id,
)
from .compiler import PolicyRuleCompiler
from .constraint_product_lattice import ConstraintProductLattice
from .context import PolicyEvalContext
from .evaluator import RuleEvaluator
from .evidence_graph import PolicyEvaluationTrace
from .fact_extractor import FactExtractor
from .facts import PolicyFactSet
from .invariants import InvariantEngine
from .preflight_planner import PreflightPlan
from .rule_index import RuleIndex
from .rule_schema import RuleHit

VALID_MODES = {"msj-enforce", "policygraph-enforce"}
RISK_SCORE = {"low": 15, "medium": 40, "high": 70, "critical": 95}
DECISION_MODEL_NAME = "AgentBrake-Fusion/MSJ Engine"
TRACE_TYPE = "BrakeTrace"


class MSJEngine:
    policy_version = "agentbrake-fusion-msj-v0.4"

    def __init__(self, domain_rules: list[dict[str, Any]] | None = None):
        self.matcher = IntentMatcher()
        self.extractor = FactExtractor()
        self.invariants = InvariantEngine()
        self.lattice = ConstraintProductLattice()
        compiled = PolicyRuleCompiler().compile(domain_rules or self._load_domain_rules())
        self.rule_index = RuleIndex(compiled)
        self.evaluator = RuleEvaluator()

    def decide(self, ctx: PolicyEvalContext, *, mode: str = "msj-enforce") -> tuple[PolicyDecision, PolicyEvaluationTrace]:
        fact_set = self.extractor.extract(ctx)
        baseline = self._baseline_decision(ctx)
        invariant_hits = self.invariants.evaluate(fact_set)
        candidates, skipped = self.rule_index.candidates(fact_set)
        rule_hits = self.evaluator.evaluate(candidates, fact_set)
        hits = [*invariant_hits, *rule_hits]
        merged, lattice_path = self.lattice.merge(baseline, hits)
        trace = PolicyEvaluationTrace.build(
            action_id=ctx.action.action_id,
            engine_mode=mode,
            policy_version=self.policy_version,
            fact_set=fact_set,
            final_decision=merged.decision,
            hits=hits,
            lattice_path=lattice_path,
            skipped_rules_summary=skipped,
        )
        merged = self._decorate_decision(merged, fact_set, hits, trace, lattice_path, skipped)
        return merged, trace

    def plan_preflight(self, decision: PolicyDecision) -> PreflightPlan:
        controls = set(decision.required_controls)
        required = bool(controls & {"sandbox_preflight", "package_preflight", "network_allowlist", "network_off", "human_approval"})
        run_even_if_blocked = os.environ.get("AGENTBRAKE_PREFLIGHT_BLOCKED", "").lower() in {"1", "true", "full", "evidence"}
        if decision.decision in {"require_confirmation", "sandbox_then_approval"}:
            required = True
        if decision.decision == "block" and run_even_if_blocked:
            required = True
        profile = (
            "package_preflight"
            if "package_preflight" in controls
            else "network-off"
            if "network_off" in controls or "no_egress" in controls
            else "dry-run"
        )
        evidence_mode = "full" if run_even_if_blocked else "summary"
        return PreflightPlan(
            required=required,
            profile=profile,
            evidence_mode=evidence_mode,
            run_even_if_blocked=run_even_if_blocked,
            decision_phase="pre_decide",
            reason_codes=decision.reason_codes,
            required_controls=decision.required_controls,
        )

    def _decorate_decision(
        self,
        decision: PolicyDecision,
        fact_set: PolicyFactSet,
        hits: list[RuleHit],
        trace: PolicyEvaluationTrace,
        lattice_path: list[dict[str, Any]],
        skipped: dict[str, Any],
    ) -> PolicyDecision:
        touched_asset_types = sorted({str(v) for v in fact_set.values("asset", "touched_type") if v})
        source_floor = next(iter(fact_set.values("source", "trust_floor")), None)
        preflight = asdict(self.plan_preflight(decision))
        graph_trace = {
            "engine": "msj_engine",
            "decision_model": DECISION_MODEL_NAME,
            "trace_type": TRACE_TYPE,
            "policy_eval_trace_id": trace.policy_eval_trace_id,
            "fact_set_id": fact_set.fact_set_id,
            "fact_hash": fact_set.content_hash,
            "fact_count": len(fact_set.facts),
            "fact_space": {
                "fact_set_id": fact_set.fact_set_id,
                "fact_hash": fact_set.content_hash,
                "evidence_namespaces": sorted({fact.namespace for fact in fact_set.facts}),
            },
            "rule_hit_count": len(hits),
            "invariant_hits": [hit.rule_id for hit in hits if hit.invariant],
            "decision_lattice_path": lattice_path,
            "constraint_product_lattice_path": lattice_path,
            "constraint_product_lattice": {
                "path": lattice_path,
                "constraints": _last_constraints(lattice_path),
            },
            "skipped_rules_summary": skipped,
            "source_trust_floor": source_floor,
            "touched_asset_types": touched_asset_types,
            "preflight_plan": preflight,
            "invariant_version": getattr(self.invariants, "version", "legacy"),
            "constraints": _last_constraints(lattice_path),
            "brake_trace": {
                "trace_id": trace.policy_eval_trace_id,
                "decision_id": decision.decision_id,
                "reason_codes": decision.reason_codes,
                "recovery_controls": decision.required_controls,
            },
        }
        return replace(
            decision,
            policy_version=self.policy_version,
            evidence_refs=list(dict.fromkeys([*decision.evidence_refs, fact_set.fact_set_id, trace.policy_eval_trace_id])),
            rule_trace=[*decision.rule_trace, graph_trace],
            explanation=self._explanation(decision, hits),
            metadata={
                **decision.metadata,
                "decision_model": DECISION_MODEL_NAME,
                "judgment_engine": "MSJ Engine",
                "fact_space_id": fact_set.fact_set_id,
                "brake_trace_id": trace.policy_eval_trace_id,
                "constraint_product": _last_constraints(lattice_path),
            },
        )

    def _baseline_decision(self, ctx: PolicyEvalContext) -> PolicyDecision:
        action = ctx.action
        intent = self.matcher.match(ctx.contract, action)
        reasons: list[str] = []
        controls: list[str] = []
        score = RISK_SCORE[action.risk]

        if ctx.context_graph.has_untrusted(action.source_ids):
            reasons.append("influenced_by_untrusted_source")
            score += 12
        if intent.contract_match in {"violation", "unknown"}:
            reasons.extend(intent.violation_reason or ["contract_violation"])
            score += 15
        elif intent.contract_match == "partial_match":
            reasons.extend(intent.violation_reason)
            score += 8
        if ctx.package_event:
            reasons.extend(ctx.package_event.reason_codes)
            if ctx.package_event.lifecycle_scripts:
                reasons.append("package_lifecycle_script_possible")
                controls.extend(["no_lifecycle_script", "secret_mount_masked"])
            if ctx.package_event.source in {"git_url", "tarball_url"}:
                controls.append("package_preflight")
                score += 15
            if ctx.package_event.risk == "critical":
                score += 10
        if ctx.secret_event:
            reasons.append(ctx.secret_event.event)
            controls.append("no_egress")
            score += 20
        if ctx.exec_trace:
            if ctx.exec_trace.network_attempts:
                reasons.append("sandbox_network_egress_attempt")
                score += 15
            if ctx.exec_trace.package_scripts:
                reasons.append("sandbox_lifecycle_observed")
            if "secret_access" in ctx.exec_trace.risk_observed:
                reasons.append("sandbox_secret_access_observed")
                score += 20
        if action.metadata.get("memory_authorization_denied"):
            reasons.append("memory_authorization_denied")
            controls.append("memory_taint_gate")
            score += 20
        return self._decision(
            action,
            "allow",
            min(score, 100),
            reasons,
            controls,
            "MSJ Engine baseline; domain rules, invariants, evidence facts, and constraints determine the final decision.",
            intent,
            ctx.package_event,
            ctx.exec_trace,
        )

    def _decision(
        self,
        action: ActionIR,
        decision: str,
        score: int,
        reasons: list[str],
        controls: list[str],
        explanation: str,
        intent: IntentDiff | None,
        package_event: PackageEvent | None,
        exec_trace: ExecTrace | None,
    ) -> PolicyDecision:
        dedup_reasons = list(dict.fromkeys(reasons))
        dedup_controls = list(dict.fromkeys(controls))
        evidence_refs = [*action.source_ids]
        if package_event:
            evidence_refs.append(package_event.package_event_id)
        if exec_trace:
            evidence_refs.append(exec_trace.exec_trace_id)
        return PolicyDecision(
            decision_id=new_id("dec"),
            action_id=action.action_id,
            decision=decision,  # type: ignore[arg-type]
            risk_score=score,
            reason_codes=dedup_reasons,
            required_controls=dedup_controls,
            explanation=explanation,
            intent_diff=intent,
            package_event_id=package_event.package_event_id if package_event else None,
            exec_trace_id=exec_trace.exec_trace_id if exec_trace else None,
            matched_rules=[],
            evidence_refs=list(dict.fromkeys(evidence_refs)),
            policy_version=self.policy_version,
            rule_trace=[
                {
                    "engine": "msj_engine",
                    "stage": "fact_space_baseline",
                    "decision_model": DECISION_MODEL_NAME,
                    "semantic_action": action.semantic_action,
                    "risk": action.risk,
                    "source_ids": action.source_ids,
                    "reason_codes": dedup_reasons,
                    "decision": decision,
                }
            ],
        )

    @staticmethod
    def _explanation(decision: PolicyDecision, hits: list[RuleHit]) -> str:
        invariant_ids = [hit.rule_id for hit in hits if hit.invariant]
        if invariant_ids:
            return f"MSJ Engine invariant(s) {', '.join(invariant_ids)} produced a non-downgradable {decision.decision} decision."
        return decision.explanation

    @staticmethod
    def _load_domain_rules() -> list[dict[str, Any]]:
        pack = os.environ.get("AGENTBRAKE_POLICY_PACK")
        path = Path(pack) if pack else Path(__file__).with_name("policies") / "core_general_agent.yaml"
        data = _load_policy_yaml(path)
        rules = data.get("rules", []) if isinstance(data, dict) else []
        if not isinstance(rules, list):
            raise ValueError(f"policy pack rules must be a list: {path}")
        return [dict(rule) for rule in rules]


PolicyGraphEngine = MSJEngine


class PolicyEngine:
    """Backward-compatible PolicyEngine entrypoint backed by the outer MSJ Engine."""

    def __init__(self, mode: str | None = None) -> None:
        self.mode = _normalise_mode(mode or os.environ.get("AGENTBRAKE_POLICY_ENGINE", "msj-enforce"))
        if self.mode not in VALID_MODES:
            self.mode = "msj-enforce"
        self.msj_engine = MSJEngine()
        self.policygraph = self.msj_engine
        self.trace_mode = os.environ.get("AGENTBRAKE_POLICY_TRACE_MODE", "full")
        self._eval_events: list[dict[str, Any]] = []
        self._fact_events: list[dict[str, Any]] = []

    @property
    def policy_version(self) -> str:
        return self.msj_engine.policy_version

    def decide(
        self,
        contract: TaskContract,
        action: ActionIR,
        asset_graph: RepoAssetGraph,
        context_graph: ContextGraph,
        package_event: PackageEvent | None = None,
        secret_event: SecretTaintEvent | None = None,
        exec_trace: ExecTrace | None = None,
        session_state: SessionState | None = None,
    ) -> PolicyDecision:
        ctx = PolicyEvalContext(
            contract,
            action,
            asset_graph,
            context_graph,
            package_event,
            secret_event,
            exec_trace,
            "post_decide" if exec_trace else "pre_decide",
            session_state,
        )
        graph_decision, trace = self.msj_engine.decide(ctx, mode=self.mode)
        event = _summary_trace(trace.to_dict()) if self.trace_mode == "summary" else trace.to_dict()
        self._eval_events.append(event)
        self._fact_events.append(
            {
                "decision_model": DECISION_MODEL_NAME,
                "fact_set_id": trace.fact_set_id,
                "fact_hash": trace.fact_hash,
                "fact_count": len(trace.fact_nodes),
                "namespace_counts": _fact_namespace_counts(trace.fact_nodes),
                "summary": _fact_summary(trace.fact_nodes),
                "policy_eval_trace_id": trace.policy_eval_trace_id,
            }
        )
        return graph_decision

    def plan_preflight(self, decision: PolicyDecision) -> PreflightPlan:
        return self.msj_engine.plan_preflight(decision)

    def consume_eval_events(self) -> list[dict[str, Any]]:
        events = self._eval_events
        self._eval_events = []
        return events

    def consume_fact_events(self) -> list[dict[str, Any]]:
        events = self._fact_events
        self._fact_events = []
        return events


def _load_policy_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except ImportError as exc:
        raise RuntimeError("PyYAML is required for MSJ Engine YAML policy packs") from exc


def _normalise_mode(mode: str) -> str:
    if mode in {"legacy", "policygraph", "policygraph-enforce"}:
        return "msj-enforce"
    return mode


def _fact_namespace_counts(nodes: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for node in nodes:
        namespace = str(node.get("namespace") or "unknown")
        counts[namespace] = counts.get(namespace, 0) + 1
    return counts


def _fact_summary(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    important = {
        "action",
        "source",
        "asset",
        "contract",
        "package",
        "secret",
        "mcp",
        "memory",
        "sandbox",
        "graph",
        "flow",
        "history",
        "constraint",
        "exec",
        "agentdojo",
    }
    out = []
    for node in nodes:
        if node.get("namespace") in important:
            out.append({k: node.get(k) for k in ("fact_id", "namespace", "key", "value", "evidence_refs")})
        if len(out) >= 40:
            break
    return out


def _last_constraints(lattice_path: list[dict[str, Any]]) -> dict[str, Any]:
    for step in reversed(lattice_path):
        constraints = step.get("constraints")
        if isinstance(constraints, dict):
            return constraints
    return {}


def _summary_trace(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy_eval_trace_id": event.get("policy_eval_trace_id"),
        "trace_type": event.get("trace_type"),
        "decision_model": event.get("decision_model"),
        "action_id": event.get("action_id"),
        "engine_mode": event.get("engine_mode"),
        "policy_version": event.get("policy_version"),
        "fact_set_id": event.get("fact_set_id"),
        "fact_hash": event.get("fact_hash"),
        "final_decision": event.get("final_decision"),
        "invariant_hits": event.get("invariant_hits", []),
        "rule_hit_count": len(event.get("rule_hits", []) or []),
        "rule_hits": [
            {
                "rule_id": hit.get("rule_id"),
                "decision": hit.get("decision"),
                "reason_codes": hit.get("reason_codes", []),
                "invariant": hit.get("invariant", False),
            }
            for hit in (event.get("rule_hits", []) or [])[:20]
        ],
        "fact_count": len(event.get("fact_nodes", []) or []),
        "namespace_counts": _fact_namespace_counts(event.get("fact_nodes", []) or []),
        "decision_lattice_path": event.get("decision_lattice_path", []),
        "constraint_product_lattice_path": event.get("constraint_product_lattice_path") or event.get("decision_lattice_path", []),
        "retrieval_trace": _summary_retrieval(event.get("retrieval_trace", {}) or {}),
        "created_at": event.get("created_at"),
    }


def _summary_retrieval(trace: dict[str, Any]) -> dict[str, Any]:
    return {
        "total_rules": trace.get("total_rules"),
        "candidate_rules": trace.get("candidate_rules"),
        "candidate_reduction_ratio": trace.get("candidate_reduction_ratio"),
        "posting_count": len(trace.get("postings", []) or []),
        "composite_hit_count": len(trace.get("composite_hits", []) or []),
        "pruned_rules": trace.get("pruned_rules"),
    }
