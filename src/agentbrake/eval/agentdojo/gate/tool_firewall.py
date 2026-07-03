from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from ..compat.types import ConfirmationMode, SanitizeMode, ToolCallContext, ablation_config_from_profile
from ..evidence.action_graph import AgentDojoActionGraphBuilder
from ..evidence.evidence import AgentDojoEvidenceBuilder
from ..evidence.fusion import AgentDojoEvidenceFusion, FusionResult
from ..evidence.state import AgentDojoStateTracker
from ..evidence.taxonomy import AgentDojoToolTaxonomy, infer_unknown_tool
from .blocked_result import BlockedActionTracker, build_blocked_tool_result, build_confirmation_required_result

_ABLATION_MODULES = (
    "provenance",
    "task_contract",
    "action_graph",
    "suite_policy",
    "recovery_guidance",
    "generic_sink_policy",
    "actiongraph_structure_edges",
    "actiongraph_provenance_edges",
    "actiongraph_dataflow_edges",
    "actiongraph_history_edges",
)


@dataclass(slots=True)
class ToolExecutionDecision:
    execute: bool
    decision: str
    reason_codes: list[str]
    safe_result: Any | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    action_graph_id: str | None = None
    action_graph_facts: dict[str, Any] = field(default_factory=dict)
    fusion_result: FusionResult | None = None
    repeated_unsafe_action: bool = False
    decision_metadata: dict[str, Any] = field(default_factory=dict)

    def to_audit_event(self) -> dict[str, Any]:
        return {
            "event_type": "agentdojo_tool_gate_decision",
            "execute": self.execute,
            "decision": self.decision,
            "reason_codes": self.reason_codes,
            "action_graph_id": self.action_graph_id,
            "action_graph_facts": self.action_graph_facts,
            "evidence": self.evidence,
            "rule_hits": [asdict(hit) for hit in self.fusion_result.rule_hits] if self.fusion_result else [],
            "repeated_unsafe_action": self.repeated_unsafe_action,
            "modules_executed": self.evidence.get("modules_executed", []),
            "modules_skipped": self.evidence.get("modules_skipped", []),
            "matched_rules": list(self.reason_codes),
            "matched_invariants": self.evidence.get("matched_invariants", []),
            "confirmation_mode": self.decision_metadata.get("confirmation_mode"),
            "confirmation_required": bool(self.decision_metadata.get("confirmation_required", False)),
            "confirmation_executed": bool(self.decision_metadata.get("confirmation_executed", False)),
            "decision_metadata": self.decision_metadata,
            "policy_engines_executed": self.evidence.get("policy_engines_executed", []),
            "policy_engine_findings": self.evidence.get("policy_engine_findings", []),
            "ablation_profile": self.evidence.get("ablation_profile"),
            "ablation_config": self.evidence.get("ablation_config", {}),
            "modules_enabled": self.evidence.get("modules_enabled", []),
            "modules_disabled": self.evidence.get("modules_disabled", []),
        }


class AgentDojoToolFirewall:
    """Tool firewall for AgentDojo benchmark runs."""

    def __init__(
        self,
        *,
        taxonomy: AgentDojoToolTaxonomy | None = None,
        state: AgentDojoStateTracker | None = None,
        graph_builder: AgentDojoActionGraphBuilder | None = None,
        evidence_builder: AgentDojoEvidenceBuilder | None = None,
        fusion: AgentDojoEvidenceFusion | None = None,
        sanitize_outputs: bool = True,
        sanitize_mode: SanitizeMode = "soft",
        eval_mode: bool = True,
        enable_taxonomy: bool = True,
        enable_state_tracker: bool = True,
        enable_action_graph: bool = True,
        enable_task_contract: bool = True,
        enable_invariants: bool = True,
        enable_recovery_guidance: bool = True,
        confirmation_mode: ConfirmationMode = "strict_eval",
        ablation_profile: str = "full",
    ) -> None:
        self.taxonomy = taxonomy or AgentDojoToolTaxonomy()
        self.state = state or AgentDojoStateTracker()
        self.state.sanitize_mode = sanitize_mode
        self.graph_builder = graph_builder or AgentDojoActionGraphBuilder()
        self.evidence_builder = evidence_builder or AgentDojoEvidenceBuilder()
        self.fusion = fusion or AgentDojoEvidenceFusion(eval_mode=eval_mode)
        self.sanitize_outputs = sanitize_outputs
        self.sanitize_mode = sanitize_mode
        self.eval_mode = eval_mode
        self.audit_events: list[dict[str, Any]] = []
        self.base_ablation_config = {
            "enable_taxonomy": enable_taxonomy,
            "enable_state_tracker": enable_state_tracker,
            "enable_action_graph": enable_action_graph,
            "enable_task_contract": enable_task_contract,
            "enable_invariants": enable_invariants,
            "enable_recovery_guidance": enable_recovery_guidance,
        }
        self._blocked_tracker = BlockedActionTracker()
        self.confirmation_mode = confirmation_mode
        self.ablation_profile = ablation_profile

    def guard_before_tool(self, context: ToolCallContext) -> ToolExecutionDecision:
        started = time.perf_counter()
        modules_executed: list[str] = []
        modules_skipped: list[str] = []
        profile = str(context.ablation_config.get("profile") or self.ablation_profile or "full")
        profile_config = ablation_config_from_profile(profile)
        ablation_config = {**profile_config.as_dict(), **context.ablation_config}
        for key, enabled in self.base_ablation_config.items():
            if key in {"enable_action_graph", "enable_task_contract", "enable_recovery_guidance"}:
                ablation_config[key] = bool(ablation_config.get(key, True)) and bool(enabled)
            else:
                ablation_config.setdefault(key, enabled)
        if "profile" not in ablation_config:
            ablation_config["profile"] = profile

        def module_enabled(name: str) -> bool:
            key = f"enable_{name}"
            return bool(ablation_config.get(key, True))

        if module_enabled("taxonomy"):
            modules_executed.append("taxonomy")
            spec = self.taxonomy.classify(context.tool_name, suite=context.suite)
        else:
            modules_skipped.append("taxonomy")
            spec = infer_unknown_tool(context.tool_name)
        if context.defense_mode == "oracle_full":
            for signature in context.attack_goal_signatures:
                self.state.add_attack_goal_signature(signature)
        if module_enabled("state_tracker"):
            modules_executed.append("state_tracker")
            self.state.observe_tool_call(context.tool_name, spec, context.tool_args)
        else:
            modules_skipped.append("state_tracker")
        initial = self.evidence_builder.build(context=context, spec=spec, state=self.state)
        if module_enabled("action_graph"):
            modules_executed.append("action_graph")
            graph_result = self.graph_builder.build(context=context, spec=spec, state=self.state, evidence=initial)
            graph_facts = graph_result.facts
            action_graph_id = graph_result.graph.graph_id
        else:
            modules_skipped.append("action_graph")
            graph_facts = {}
            action_graph_id = None
        evidence = self.evidence_builder.build(context=context, spec=spec, state=self.state, graph_facts=graph_facts)
        evidence.action_graph_id = action_graph_id
        for name in ("task_contract", "invariants"):
            if module_enabled(name):
                modules_executed.append(name)
            else:
                modules_skipped.append(name)
        evidence.facts["ablation_config"] = ablation_config
        evidence.facts["ablation_profile"] = str(ablation_config.get("profile") or profile)
        evidence.facts["modules_executed"] = modules_executed
        evidence.facts["modules_skipped"] = modules_skipped
        evidence.facts["modules_enabled"] = [name for name in _ABLATION_MODULES if bool(ablation_config.get(f"enable_{name}", True))]
        evidence.facts["modules_disabled"] = [name for name in _ABLATION_MODULES if not bool(ablation_config.get(f"enable_{name}", True))]
        evidence.facts["matched_invariants"] = [] if not module_enabled("invariants") else evidence.facts.get("matched_invariants", [])
        fusion = self.fusion.decide(evidence)
        execute, public_decision, decision_metadata = self._resolve_execution_for_decision(
            fusion=fusion,
            context=context,
            evidence=evidence.facts,
            action_graph_facts=graph_facts,
        )
        repeated = False
        safe = None
        if not execute:
            if public_decision == "require_confirmation":
                safe = build_confirmation_required_result(
                    context,
                    fusion,
                    recovery_guidance_enabled=module_enabled("recovery_guidance"),
                )
            else:
                safe = build_blocked_tool_result(
                    context,
                    fusion,
                    recovery_guidance_enabled=module_enabled("recovery_guidance"),
                )
            retry_count = self._blocked_tracker.record(str(safe["same_action_retry_key"]))
            repeated = retry_count > 1
            if repeated and public_decision != "require_confirmation":
                safe = build_blocked_tool_result(
                    context,
                    fusion,
                    repeated_unsafe_action=True,
                    recovery_guidance_enabled=module_enabled("recovery_guidance"),
                )
            self.state.observe_tool_call(
                context.tool_name,
                spec,
                context.tool_args,
                event_status="blocked",
                decision=public_decision,
                execute=False,
                reason_codes=fusion.reason_codes,
                same_action_retry_key=str(safe["same_action_retry_key"]),
            )
        decision = ToolExecutionDecision(
            execute=execute,
            decision=public_decision,
            reason_codes=fusion.reason_codes,
            safe_result=safe,
            evidence=evidence.facts,
            action_graph_id=action_graph_id,
            action_graph_facts=graph_facts,
            fusion_result=fusion,
            repeated_unsafe_action=repeated,
            decision_metadata=decision_metadata,
        )
        event = decision.to_audit_event()
        event["policy_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
        self.audit_events.append(event)
        return decision

    def _resolve_execution_for_decision(
        self,
        *,
        fusion: FusionResult,
        context: ToolCallContext,
        evidence: dict[str, Any],
        action_graph_facts: dict[str, Any],
    ) -> tuple[bool, str, dict[str, Any]]:
        metadata: dict[str, Any] = {
            "confirmation_mode": self.confirmation_mode,
            "confirmation_required": fusion.decision == "require_confirmation",
            "confirmation_executed": False,
            "ablation_profile": evidence.get("ablation_profile"),
        }
        if fusion.decision in {"allow", "allow_in_sandbox"}:
            if self.confirmation_mode in {"oracle_user_eval", "gateway_eval"} and _membership_confirmation_allowed(evidence, action_graph_facts):
                metadata["confirmation_required"] = True
                metadata["confirmation_executed"] = True
                if self.confirmation_mode == "gateway_eval":
                    metadata["gateway_confirmation_counted_separately"] = True
                    metadata["gateway_user_confirmation_allowed"] = True
                else:
                    metadata["oracle_user_confirmation_allowed"] = True
                return True, "require_confirmation", metadata
            return True, fusion.decision, metadata
        if fusion.decision == "require_confirmation":
            public_decision = "require_confirmation"
            membership_confirmation = (
                evidence.get("agentdojo.tool_group") == "membership_mutation"
                and bool(evidence.get("agentdojo.task_authorized"))
                and bool(evidence.get("agentdojo.args_match_user_entity"))
                and not bool(action_graph_facts.get("graph.has_private_to_external_edge"))
                and not bool(action_graph_facts.get("graph.has_private_to_executed_external_edge"))
            )
            external_send_confirmation = (
                evidence.get("agentdojo.tool_group") == "external_send"
                and bool(evidence.get("agentdojo.task_authorized"))
                and bool(evidence.get("agentdojo.args_match_user_entity"))
                and not bool(evidence.get("agentdojo.args_match_untrusted_entity"))
                and not bool(evidence.get("agentdojo.attack_goal_overlap"))
                and not bool(action_graph_facts.get("graph.has_private_to_executed_external_edge"))
                and not bool(action_graph_facts.get("graph.has_untrusted_to_executed_side_effect_edge"))
            )
            allow_user_confirmation = membership_confirmation or external_send_confirmation or (
                bool(evidence.get("agentdojo.task_authorized"))
                and not bool(evidence.get("agentdojo.args_match_untrusted_entity"))
                and not bool(evidence.get("agentdojo.attack_goal_overlap"))
                and not bool(action_graph_facts.get("graph.has_private_to_external_edge"))
                and not bool(action_graph_facts.get("graph.has_private_to_executed_external_edge"))
                and not bool(action_graph_facts.get("graph.has_untrusted_to_executed_side_effect_edge"))
            )
            if self.confirmation_mode == "oracle_user_eval":
                metadata["oracle_user_confirmation_allowed"] = allow_user_confirmation
                metadata["confirmation_executed"] = allow_user_confirmation
                return allow_user_confirmation, public_decision, metadata
            metadata["gateway_confirmation_counted_separately"] = self.confirmation_mode == "gateway_eval"
            if self.confirmation_mode == "gateway_eval":
                metadata["gateway_user_confirmation_allowed"] = allow_user_confirmation
                metadata["confirmation_executed"] = allow_user_confirmation
                return allow_user_confirmation, public_decision, metadata
            return False, public_decision, metadata
        return False, fusion.decision, metadata

    def observe_after_tool(self, context: ToolCallContext, raw_result: Any) -> Any:
        started = time.perf_counter()
        spec = self.taxonomy.classify(context.tool_name, suite=context.suite)
        self.state.observe_tool_call(context.tool_name, spec, context.tool_args, event_status="executed", decision="allow", execute=True)
        event = self.state.observe_tool_result(context.tool_name, spec, raw_result)
        sanitized = self.state.sanitize_tool_output(raw_result, mode=self.sanitize_mode) if self.sanitize_outputs else raw_result
        self.audit_events.append(
            {
                "event_type": "agentdojo_tool_result_observed",
                "suite": context.suite,
                "tool_name": context.tool_name,
                "tool_group": spec.group,
                "result_event": asdict(event),
                "state": self.state.as_dict(),
                "sanitized": sanitized != raw_result,
                "observe_ms": round((time.perf_counter() - started) * 1000.0, 3),
            }
        )
        return sanitized

    def run_guarded_tool(self, context: ToolCallContext, original_tool: Callable[..., Any]) -> tuple[Any, ToolExecutionDecision]:
        decision = self.guard_before_tool(context)
        if not decision.execute:
            return decision.safe_result, decision
        raw = original_tool(**context.tool_args)
        return self.observe_after_tool(context, raw), decision


def summarize_agentdojo_firewall_audit(events: list[dict[str, Any]]) -> dict[str, Any]:
    decision_events = [event for event in events if event.get("event_type") == "agentdojo_tool_gate_decision"]
    result_events = [event for event in events if event.get("event_type") == "agentdojo_tool_result_observed"]
    policy_latencies = [float(event.get("policy_ms", 0.0)) for event in decision_events if isinstance(event.get("policy_ms"), (int, float))]
    registered = 0
    unknown = 0
    blocked = 0
    repeated_blocked = 0
    rule_hits: dict[str, int] = {}
    for event in decision_events:
        evidence = event.get("evidence") or {}
        if evidence.get("agentdojo.unknown_tool"):
            unknown += 1
        else:
            registered += 1
        if not event.get("execute", True):
            blocked += 1
        if event.get("repeated_unsafe_action"):
            repeated_blocked += 1
        for hit in event.get("rule_hits") or []:
            rule_id = str(hit.get("rule_id", ""))
            if rule_id:
                rule_hits[rule_id] = rule_hits.get(rule_id, 0) + 1
    total = len(decision_events)
    return {
        "registered_tool_rate": 0.0 if total == 0 else registered / total,
        "unknown_tool_rate": 0.0 if total == 0 else unknown / total,
        "total_tool_calls_gated": total,
        "tool_gate_decision_count": total,
        "blocked_tool_calls": blocked,
        "repeated_block_count": repeated_blocked,
        "safe_blocked_result": blocked,
        "allow": total - blocked,
        "block": blocked,
        "policy_p50_ms": _percentile(policy_latencies, 0.5),
        "policy_p95_ms": _percentile(policy_latencies, 0.95),
        "rule_hit_counts": dict(sorted(rule_hits.items())),
        "result_events": len(result_events),
    }


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((len(ordered) - 1) * pct)))
    return float(ordered[idx])


def _membership_confirmation_allowed(evidence: dict[str, Any], action_graph_facts: dict[str, Any]) -> bool:
    return (
        evidence.get("agentdojo.tool_group") == "membership_mutation"
        and bool(evidence.get("agentdojo.task_authorized"))
        and (bool(evidence.get("agentdojo.args_match_user_entity")) or not bool(evidence.get("agentdojo.attack_goal_overlap")))
        and not bool(action_graph_facts.get("graph.has_private_to_external_edge"))
        and not bool(action_graph_facts.get("graph.has_private_to_executed_external_edge"))
        and not bool(action_graph_facts.get("graph.has_untrusted_to_executed_side_effect_edge"))
    )


