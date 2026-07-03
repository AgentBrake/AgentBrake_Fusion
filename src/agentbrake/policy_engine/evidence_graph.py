"""BrakeTrace evidence graph emitted by outer MSJ Engine decisions."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Any

from ..models import Decision, new_id, utc_now
from .facts import PolicyFactSet
from .rule_schema import RuleHit


@dataclass(slots=True)
class PolicyEvaluationTrace:
    policy_eval_trace_id: str
    action_id: str
    engine_mode: str
    policy_version: str
    fact_set_id: str
    fact_hash: str
    final_decision: Decision
    invariant_hits: list[str]
    rule_hits: list[dict[str, Any]]
    decision_lattice_path: list[dict[str, Any]]
    constraint_product_lattice_path: list[dict[str, Any]] = field(default_factory=list)
    trace_type: str = "BrakeTrace"
    decision_model: str = "AgentBrake-Fusion/MSJ Engine"
    fact_nodes: list[dict[str, Any]] = field(default_factory=list)
    predicate_nodes: list[dict[str, Any]] = field(default_factory=list)
    rule_nodes: list[dict[str, Any]] = field(default_factory=list)
    lattice_nodes: list[dict[str, Any]] = field(default_factory=list)
    retrieval_nodes: list[dict[str, Any]] = field(default_factory=list)
    action_graph_nodes: list[dict[str, Any]] = field(default_factory=list)
    history_nodes: list[dict[str, Any]] = field(default_factory=list)
    constraint_nodes: list[dict[str, Any]] = field(default_factory=list)
    invariant_nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, str]] = field(default_factory=list)
    skipped_rules_summary: dict[str, Any] = field(default_factory=dict)
    retrieval_trace: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)

    @classmethod
    def build(
        cls,
        *,
        action_id: str,
        engine_mode: str,
        policy_version: str,
        fact_set: PolicyFactSet,
        final_decision: Decision,
        hits: list[RuleHit],
        lattice_path: list[dict[str, Any]],
        skipped_rules_summary: dict[str, Any] | None = None,
    ) -> "PolicyEvaluationTrace":
        retrieval_trace = (skipped_rules_summary or {}).get("retrieval_trace", {}) if isinstance(skipped_rules_summary, dict) else {}
        if os.getenv("AGENTBRAKE_EVIDENCE_GRAPH_MODE", "full") == "summary" and final_decision not in {"block", "quarantine"}:
            retrieval_summary = _summary_retrieval_trace(retrieval_trace)
            return cls(
                policy_eval_trace_id=new_id("peval"),
                action_id=action_id,
                engine_mode=engine_mode,
                policy_version=policy_version,
                fact_set_id=fact_set.fact_set_id,
                fact_hash=fact_set.content_hash,
                final_decision=final_decision,
                invariant_hits=[h.rule_id for h in hits if h.invariant],
                rule_hits=[asdict(h) for h in hits],
                constraint_product_lattice_path=lattice_path,
                trace_type="BrakeTrace",
                decision_model="AgentBrake-Fusion/MSJ Engine",
                fact_nodes=[
                    {
                        "id": fact.fact_id,
                        "fact_id": fact.fact_id,
                        "namespace": fact.namespace,
                        "key": fact.key,
                        "value": fact.value,
                        "evidence_refs": fact.evidence_refs,
                        "confidence": fact.confidence,
                        "metadata": fact.metadata,
                    }
                    for fact in fact_set.facts
                    if fact.namespace in {"action", "source", "contract", "agentdojo"}
                ][:80],
                decision_lattice_path=lattice_path,
                skipped_rules_summary=skipped_rules_summary or {},
                retrieval_trace=retrieval_summary,
            )
        graph = _causal_graph(fact_set, hits, lattice_path, retrieval_trace)
        return cls(
            policy_eval_trace_id=new_id("peval"),
            action_id=action_id,
            engine_mode=engine_mode,
            policy_version=policy_version,
            fact_set_id=fact_set.fact_set_id,
            fact_hash=fact_set.content_hash,
            final_decision=final_decision,
            invariant_hits=[h.rule_id for h in hits if h.invariant],
            rule_hits=[asdict(h) for h in hits],
            constraint_product_lattice_path=lattice_path,
            trace_type="BrakeTrace",
            decision_model="AgentBrake-Fusion/MSJ Engine",
            fact_nodes=graph["fact_nodes"],
            predicate_nodes=graph["predicate_nodes"],
            rule_nodes=graph["rule_nodes"],
            lattice_nodes=graph["lattice_nodes"],
            retrieval_nodes=graph["retrieval_nodes"],
            action_graph_nodes=graph["action_graph_nodes"],
            history_nodes=graph["history_nodes"],
            constraint_nodes=graph["constraint_nodes"],
            invariant_nodes=graph["invariant_nodes"],
            edges=graph["edges"],
            decision_lattice_path=lattice_path,
            skipped_rules_summary=skipped_rules_summary or {},
            retrieval_trace=retrieval_trace,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _causal_graph(
    fact_set: PolicyFactSet, hits: list[RuleHit], lattice_path: list[dict[str, Any]], retrieval_trace: dict[str, Any] | None = None
) -> dict[str, list[dict[str, Any]]]:
    fact_nodes = [
        {
            "id": fact.fact_id,
            "fact_id": fact.fact_id,
            "namespace": fact.namespace,
            "key": fact.key,
            "value": fact.value,
            "evidence_refs": fact.evidence_refs,
            "confidence": fact.confidence,
            "metadata": fact.metadata,
        }
        for fact in fact_set.facts
    ]
    predicate_nodes: list[dict[str, Any]] = []
    rule_nodes: list[dict[str, Any]] = []
    lattice_nodes: list[dict[str, Any]] = []
    retrieval_nodes: list[dict[str, Any]] = []
    action_graph_nodes: list[dict[str, Any]] = []
    history_nodes: list[dict[str, Any]] = []
    constraint_nodes: list[dict[str, Any]] = []
    invariant_nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    for fact in fact_set.facts:
        if fact.namespace == "graph":
            node_id = f"action_graph_{fact.fact_id}"
            action_graph_nodes.append(
                {
                    "id": node_id,
                    "kind": "action_graph_node",
                    "fact_id": fact.fact_id,
                    "key": fact.key,
                    "value": fact.value,
                    "evidence_refs": fact.evidence_refs,
                    "confidence": fact.confidence,
                    "parser": fact.metadata.get("parser"),
                    "observed": fact.metadata.get("observed", False),
                    "warnings": fact.metadata.get("warnings", []),
                    "metadata": fact.metadata,
                }
            )
            edges.append({"from": fact.fact_id, "to": node_id, "relation": "summarizes"})
        elif fact.namespace == "history":
            node_id = f"history_{fact.fact_id}"
            history_nodes.append(
                {
                    "id": node_id,
                    "kind": "history_node",
                    "fact_id": fact.fact_id,
                    "key": fact.key,
                    "value": fact.value,
                    "evidence_refs": fact.evidence_refs,
                    "confidence": fact.confidence,
                    "state_hash": fact.metadata.get("state_hash"),
                    "restore_source": fact.metadata.get("restore_source"),
                    "metadata": fact.metadata,
                }
            )
            edges.append({"from": node_id, "to": fact.fact_id, "relation": "provides_fact"})
        elif fact.namespace == "trace" and fact.key == "enriched_graph":
            node_id = f"action_graph_trace_{fact.fact_id}"
            action_graph_nodes.append(
                {
                    "id": node_id,
                    "kind": "trace_enrichment_node",
                    "fact_id": fact.fact_id,
                    "key": fact.key,
                    "value": fact.value,
                    "evidence_refs": fact.evidence_refs,
                    "confidence": fact.confidence,
                    "observed": True,
                    "metadata": fact.metadata,
                }
            )
            edges.append({"from": node_id, "to": fact.fact_id, "relation": "observed_trace"})
    for idx, posting in enumerate((retrieval_trace or {}).get("postings", []) or []):
        node_id = f"retrieval_{idx}"
        retrieval_nodes.append({"id": node_id, "kind": "posting", **posting})
        key = str(posting.get("key") or "")
        path, _, value = key.partition("=")
        for fact in fact_set.facts:
            if f"{fact.namespace}.{fact.key}" == path and str(fact.value).lower() == value:
                edges.append({"from": fact.fact_id, "to": node_id, "relation": "retrieves"})
        for rule_id in posting.get("rule_ids", []) or []:
            edges.append({"from": node_id, "to": str(rule_id), "relation": "candidate"})
    for hit in hits:
        predicate_ids: list[str] = []
        for pred in hit.predicates:
            p = asdict(pred) if hasattr(pred, "__dataclass_fields__") else dict(pred)
            pred_id = str(p.get("predicate_id") or p.get("fact_id") or new_id("pred"))
            p["id"] = pred_id
            p["rule_id"] = hit.rule_id
            predicate_nodes.append(p)
            predicate_ids.append(pred_id)
            for fact_id in p.get("matched_fact_ids", []) or ([p.get("fact_id")] if p.get("fact_id") else []):
                edges.append({"from": str(fact_id), "to": pred_id, "relation": "matched"})
            edges.append({"from": pred_id, "to": hit.rule_id, "relation": "predicate_of"})
        rule_nodes.append(
            {
                "id": hit.rule_id,
                "rule_id": hit.rule_id,
                "decision": hit.decision,
                "invariant": hit.invariant,
                "predicate_ids": predicate_ids,
            }
        )
        if hit.invariant:
            invariant_nodes.append(
                {
                    "id": f"invariant_{hit.rule_id}",
                    "kind": "invariant_node",
                    "rule_id": hit.rule_id,
                    "decision": hit.decision,
                    "constraints": hit.constraints,
                    "predicate_ids": predicate_ids,
                }
            )
            edges.append({"from": f"invariant_{hit.rule_id}", "to": hit.rule_id, "relation": "semantic_invariant"})
    previous = ""
    for idx, step in enumerate(lattice_path):
        node_id = f"lattice_{idx}"
        lattice_nodes.append({"id": node_id, **step})
        if isinstance(step.get("constraints"), dict):
            constraint_id = f"constraint_{idx}"
            constraint_nodes.append(
                {"id": constraint_id, "kind": "constraint_node", "via": step.get("via"), "constraints": step["constraints"]}
            )
            edges.append({"from": constraint_id, "to": node_id, "relation": "constraint_join"})
        via = str(step.get("via") or "")
        if via and via not in {"policygraph_baseline", "msj_baseline"}:
            edges.append({"from": via, "to": node_id, "relation": "merged_into"})
        if previous:
            edges.append({"from": previous, "to": node_id, "relation": "next"})
        previous = node_id
    if previous:
        edges.append({"from": previous, "to": "final_decision", "relation": "final"})
    return {
        "fact_nodes": fact_nodes,
        "predicate_nodes": predicate_nodes,
        "rule_nodes": rule_nodes,
        "lattice_nodes": lattice_nodes,
        "retrieval_nodes": retrieval_nodes,
        "action_graph_nodes": action_graph_nodes,
        "history_nodes": history_nodes,
        "constraint_nodes": constraint_nodes,
        "invariant_nodes": invariant_nodes,
        "edges": edges,
    }


def _summary_retrieval_trace(trace: dict[str, Any] | None) -> dict[str, Any]:
    trace = trace or {}
    return {
        "total_rules": trace.get("total_rules"),
        "candidate_rules": trace.get("candidate_rules"),
        "candidate_reduction_ratio": trace.get("candidate_reduction_ratio"),
        "posting_count": len(trace.get("postings", []) or []),
        "composite_hit_count": len(trace.get("composite_hits", []) or []),
    }
