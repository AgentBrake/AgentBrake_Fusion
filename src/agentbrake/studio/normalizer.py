"""Normalize AuditLog/Approval/Bench data into Studio Pro view models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ActionDetail, RunSummary, StudioEvent
from .redaction import redact_value

PHASES = {
    "gateway_pre_call": "request",
    "source_ingested": "context",
    "task_contract": "contract",
    "gateway_post_call": "model",
    "instruction_ir": "instruction",
    "action_parsed": "action",
    "action_graph": "action",
    "action_graph_enriched": "action",
    "session_state_update": "policy",
    "session_state_restore": "policy",
    "session_state_persisted": "policy",
    "constraint_lattice_trace": "policy",
    "secret_event": "evidence",
    "package_event": "evidence",
    "mcp_invocation": "evidence",
    "memory_event": "evidence",
    "exec_trace": "sandbox",
    "policy_fact_set": "policy",
    "policy_decision": "policy",
    "policy_eval_trace": "policy",
    "policy_runtime": "policy",
    "gateway_approval_request": "approval",
    "gateway_response": "response",
}

DANGEROUS = {
    "install_git_dependency",
    "install_tarball_dependency",
    "install_registry_dependency",
    "read_secret_file",
    "send_network_request",
    "publish_artifact",
    "modify_ci_pipeline",
    "modify_registry_config",
    "invoke_destructive_mcp_tool",
    "unknown_side_effect",
}


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    events: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    # JSONL audit files can be tailed while another process is writing.
                    # Skip incomplete/corrupt lines so Studio stays usable.
                    continue
    return events


def normalize_audit_events(
    events: list[dict[str, Any]], *, agent_name: str = "local", demo_scenario_id: str | None = None
) -> list[StudioEvent]:
    normalized: list[StudioEvent] = []
    trace_by_session: dict[str, str] = {}
    for event in events:
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        session_id = str(event.get("session_id") or "")
        if session_id and payload.get("trace_id") and session_id not in trace_by_session:
            trace_by_session[session_id] = str(payload["trace_id"])
    for idx, event in enumerate(events):
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        trace_id = str(
            payload.get("trace_id") or trace_by_session.get(str(event.get("session_id") or "")) or event.get("session_id") or "run_default"
        )
        event_type = str(event.get("event_type") or "event")
        run_id = str(payload.get("run_id") or trace_id)
        span_id = _span_id(event_type, payload, event, idx)
        normalized.append(
            StudioEvent(
                schema_version="studio.event.v1",
                event_id=str(event.get("event_id") or f"evt_{idx}"),
                timestamp=str(event.get("timestamp") or event.get("created_at") or ""),
                run_id=run_id,
                session_id=str(event.get("session_id") or ""),
                request_id=str(payload.get("turn_id") or payload.get("request_id") or run_id),
                span_id=span_id,
                parent_span_id=_parent_span(event_type, payload, event),
                event_index=idx,
                type=event_type,
                phase=PHASES.get(event_type, "other"),
                severity=_severity(event_type, payload),
                summary=_summary(event_type, payload),
                agent_name=str(payload.get("agent_name") or agent_name),
                demo_scenario_id=str(payload.get("demo_scenario_id") or demo_scenario_id or "") or None,
                payload=redact_value(_payload_for_ui(event_type, payload, event)),
            )
        )
    return normalized


def build_run_summaries(events: list[StudioEvent]) -> list[RunSummary]:
    runs: dict[str, RunSummary] = {}
    for event in events:
        run = runs.get(event.run_id)
        if not run:
            run = RunSummary(
                event.run_id,
                event.session_id,
                event.timestamp,
                event.timestamp,
                agent_name=event.agent_name,
                demo_scenario_id=event.demo_scenario_id,
            )
            runs[event.run_id] = run
        run.updated_at = event.timestamp or run.updated_at
        run.event_count += 1
        if event.type == "action_parsed":
            run.action_count += 1
        if event.phase == "approval":
            run.approval_count += 1
        if event.severity == "critical":
            run.critical_count += 1
        decision = event.payload.get("decision") or event.payload.get("effective_decision")
        if decision:
            run.latest_decision = str(decision)
        if decision in {"block", "quarantine", "require_confirmation", "sandbox_then_approval"} or event.payload.get("blocked_count"):
            run.blocked_count += 1
    return sorted(runs.values(), key=lambda r: r.updated_at, reverse=True)


def build_action_detail(events: list[StudioEvent], action_id: str) -> ActionDetail | None:
    related = [e for e in events if e.payload.get("action_id") == action_id or e.span_id == action_id]
    if not related:
        return None
    detail = ActionDetail(action_id=action_id, run_id=related[0].run_id)
    source_ids: set[str] = set()
    for event in related:
        if event.type == "action_parsed":
            detail.action = dict(event.payload)
            source_ids.update(str(s) for s in event.payload.get("source_ids", []) or [])
            if isinstance(event.payload.get("action_graph"), dict):
                detail.action_graph = dict(event.payload["action_graph"])
        elif event.type in {"action_graph", "action_graph_enriched"}:
            detail.action_graph = dict(event.payload)
        elif event.type in {"session_state_update", "session_state_restore", "session_state_persisted"}:
            payload = dict(event.payload)
            detail.session_state = dict(payload.get("state") or payload)
        elif event.type == "policy_decision":
            detail.decision = dict(event.payload)
        elif event.type == "policy_runtime":
            detail.runtime = dict(event.payload)
        elif event.type == "instruction_ir":
            detail.instruction = dict(event.payload)
        elif event.type == "policy_fact_set":
            detail.policy_fact_set = dict(event.payload)
        elif event.type == "policy_eval_trace":
            detail.policy_eval_trace = dict(event.payload)
            detail.policy_predicates = _predicate_matrix(event.payload)
            detail.policy_lattice_path = list(
                event.payload.get("constraint_product_lattice_path") or event.payload.get("decision_lattice_path") or []
            )
            detail.policy_causal_graph = {
                "fact_nodes": list(event.payload.get("fact_nodes") or []),
                "predicate_nodes": list(event.payload.get("predicate_nodes") or []),
                "rule_nodes": list(event.payload.get("rule_nodes") or []),
                "lattice_nodes": list(event.payload.get("lattice_nodes") or []),
                "retrieval_nodes": list(event.payload.get("retrieval_nodes") or []),
                "action_graph_nodes": list(event.payload.get("action_graph_nodes") or []),
                "history_nodes": list(event.payload.get("history_nodes") or []),
                "constraint_nodes": list(event.payload.get("constraint_nodes") or []),
                "invariant_nodes": list(event.payload.get("invariant_nodes") or []),
                "edges": list(event.payload.get("edges") or []),
            }
        detail.evidence_events.append(event.to_dict())
    for event in events:
        if event.type == "source_ingested" and event.payload.get("source_id") in source_ids:
            detail.sources.append(event.payload)
    return detail


def build_action_judgment(events: list[StudioEvent], action_id: str) -> dict[str, Any] | None:
    detail = build_action_detail(events, action_id)
    if detail is None:
        return None
    return judgment_view_model(detail)


def judgment_view_model(detail: ActionDetail) -> dict[str, Any]:
    trace = detail.policy_eval_trace or {}
    decision = detail.decision or {}
    action = detail.action or {}
    fact_nodes = list(trace.get("fact_nodes") or detail.policy_fact_set.get("summary") or [])
    predicate_rows = list(detail.policy_predicates or _predicate_matrix(trace))
    rule_nodes = list(trace.get("rule_nodes") or decision.get("matched_rules") or [])
    invariant_hits = [rule for rule in rule_nodes if rule.get("invariant") or str(rule.get("rule_id") or "").startswith("INV-")]
    final_decision = str(trace.get("final_decision") or decision.get("decision") or detail.runtime.get("effective_decision") or "unknown")
    return {
        "schema_version": "studio.judgment.v1",
        "action_id": detail.action_id,
        "run_id": detail.run_id,
        "action_summary": {
            "raw_action": action.get("raw_action"),
            "semantic_action": action.get("semantic_action"),
            "risk": action.get("risk"),
            "parser_confidence": action.get("parser_confidence"),
        },
        "evidence_groups": _judgment_evidence_groups(detail, fact_nodes),
        "fact_set": detail.policy_fact_set,
        "fact_nodes": fact_nodes,
        "invariant_hits": invariant_hits,
        "candidate_rules": _candidate_rules(trace, rule_nodes),
        "predicate_rows": predicate_rows,
        "lattice_path": list(
            detail.policy_lattice_path or trace.get("constraint_product_lattice_path") or trace.get("decision_lattice_path") or []
        ),
        "causal_graph": detail.policy_causal_graph
        or {
            "fact_nodes": fact_nodes,
            "predicate_nodes": list(trace.get("predicate_nodes") or []),
            "rule_nodes": rule_nodes,
            "lattice_nodes": list(trace.get("lattice_nodes") or []),
            "retrieval_nodes": list(trace.get("retrieval_nodes") or []),
            "action_graph_nodes": list(trace.get("action_graph_nodes") or []),
            "history_nodes": list(trace.get("history_nodes") or []),
            "constraint_nodes": list(trace.get("constraint_nodes") or []),
            "invariant_nodes": list(trace.get("invariant_nodes") or []),
            "edges": list(trace.get("edges") or []),
        },
        "final_decision": final_decision,
        "reason_codes": list(decision.get("reason_codes") or []),
        "required_controls": list(decision.get("required_controls") or []),
        "evidence_refs": list(decision.get("evidence_refs") or []),
        "why_text": _why_text(detail, final_decision, invariant_hits),
        "skipped_rules_summary": trace.get("skipped_rules_summary") or {},
        "retrieval_trace": trace.get("retrieval_trace") or (trace.get("skipped_rules_summary") or {}).get("retrieval_trace") or {},
        "policy_eval_trace_id": trace.get("policy_eval_trace_id"),
        "fact_hash": trace.get("fact_hash") or detail.policy_fact_set.get("fact_hash"),
        "constraints": _constraints_from_decision(decision),
    }


def _predicate_matrix(trace: dict[str, Any]) -> list[dict[str, Any]]:
    rules = {str(rule.get("rule_id") or rule.get("id")): rule for rule in trace.get("rule_nodes") or [] if isinstance(rule, dict)}
    rows: list[dict[str, Any]] = []
    for predicate in trace.get("predicate_nodes") or []:
        if not isinstance(predicate, dict):
            continue
        rule_id = str(predicate.get("rule_id") or "")
        rule = rules.get(rule_id, {})
        rows.append(
            {
                "rule_id": rule_id,
                "rule_decision": rule.get("decision"),
                "rule_invariant": bool(rule.get("invariant")),
                "predicate_id": predicate.get("predicate_id") or predicate.get("id") or predicate.get("fact_id"),
                "path": predicate.get("path") or ".".join(str(part) for part in (predicate.get("namespace"), predicate.get("key")) if part),
                "operator": predicate.get("operator") or "fact_match",
                "expected": predicate.get("expected"),
                "actual": predicate.get("actual", predicate.get("value")),
                "matched": bool(predicate.get("matched")),
                "matched_fact_ids": list(predicate.get("matched_fact_ids") or ([predicate["fact_id"]] if predicate.get("fact_id") else [])),
                "evidence_refs": list(predicate.get("evidence_refs") or []),
            }
        )
    return rows


def _candidate_rules(trace: dict[str, Any], rule_nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidate_count = int((trace.get("skipped_rules_summary") or {}).get("candidate_rules") or len(rule_nodes))
    return [{"rule_id": rule.get("rule_id") or rule.get("id"), **rule} for rule in rule_nodes] or [
        {"rule_id": f"candidate_{idx + 1}"} for idx in range(candidate_count)
    ]


def _constraints_from_decision(decision: dict[str, Any]) -> dict[str, Any]:
    metadata = decision.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("decision_constraints"), dict):
        return dict(metadata["decision_constraints"])
    for trace in reversed(decision.get("rule_trace", []) or []):
        if isinstance(trace, dict) and isinstance(trace.get("constraints"), dict):
            return dict(trace["constraints"])
    return {}


def _judgment_evidence_groups(detail: ActionDetail, fact_nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _group("source", "来源证据", "warning", _source_items(detail.sources, fact_nodes)),
        _group("action", "动作证据", "info", _fact_items(fact_nodes, "action", "ActionIR", fallback=detail.action)),
        _group("asset", "资产证据", "warning", _fact_items(fact_nodes, "asset", "AssetGraph")),
        _group("contract", "任务边界证据", "info", _fact_items(fact_nodes, "contract", "TaskContract", fallback=detail.instruction)),
        _group("security", "安全事件证据", "critical", _security_items(detail.evidence_events, fact_nodes)),
        _group("execution", "执行预检证据", "normal", _execution_items(detail.evidence_events)),
    ]


def _group(group_id: str, label: str, severity: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {"group_id": group_id, "label": label, "severity": severity, "items": items}


def _source_items(sources: list[dict[str, Any]], fact_nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = [
        {
            "id": str(source.get("source_id") or f"source_{idx}"),
            "label": str(source.get("source_type") or "上下文来源"),
            "value": source.get("trust_level") or source.get("trust") or "unknown",
            "evidence_refs": [str(source.get("source_id"))] if source.get("source_id") else [],
            "source_module": "ContextGraph",
        }
        for idx, source in enumerate(sources)
    ]
    items.extend(_fact_items(fact_nodes, "source", "ContextGraph"))
    return items


def _security_items(events: list[dict[str, Any]], fact_nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for event in events:
        event_type = event.get("type")
        if event_type not in {"secret_event", "package_event", "mcp_invocation", "memory_event"}:
            continue
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        items.append(
            {
                "id": str(event.get("span_id") or event.get("event_id") or event_type),
                "label": str(event_type).replace("_", " "),
                "value": payload.get("event") or payload.get("source") or payload.get("decision") or payload.get("summary") or event_type,
                "evidence_refs": list(payload.get("evidence_refs") or []),
                "source_module": _source_module_for_event(str(event_type)),
            }
        )
    for namespace, module in (("secret", "SecretSentry"), ("package", "PackageGuard"), ("mcp", "MCPProxy"), ("memory", "MemoryStore")):
        items.extend(_fact_items(fact_nodes, namespace, module))
    return items


def _execution_items(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for event in events:
        if event.get("type") != "exec_trace":
            continue
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        items.append(
            {
                "id": str(payload.get("exec_trace_id") or event.get("span_id") or event.get("event_id")),
                "label": "沙箱预检",
                "value": {
                    "risk_observed": payload.get("risk_observed"),
                    "evidence_mode": payload.get("evidence_mode"),
                    "profile": payload.get("profile"),
                },
                "evidence_refs": [str(payload.get("exec_trace_id"))] if payload.get("exec_trace_id") else [],
                "source_module": "SandboxRunner",
            }
        )
    return items


def _fact_items(
    fact_nodes: list[dict[str, Any]], namespace: str, source_module: str, fallback: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    items = [
        {
            "id": str(fact.get("fact_id") or fact.get("id") or f"{namespace}.{fact.get('key')}"),
            "label": f"{namespace}.{fact.get('key')}",
            "value": fact.get("value"),
            "evidence_refs": list(fact.get("evidence_refs") or []),
            "source_module": source_module,
        }
        for fact in fact_nodes
        if fact.get("namespace") == namespace
    ]
    if items or not fallback:
        return items
    return [
        {
            "id": f"{namespace}.{key}",
            "label": f"{namespace}.{key}",
            "value": value,
            "evidence_refs": [],
            "source_module": source_module,
        }
        for key, value in fallback.items()
        if value not in (None, "", [], {})
    ][:8]


def _source_module_for_event(event_type: str) -> str:
    return {
        "secret_event": "SecretSentry",
        "package_event": "PackageGuard",
        "mcp_invocation": "MCPProxy",
        "memory_event": "MemoryStore",
    }.get(event_type, "MSJ Engine")


def _why_text(detail: ActionDetail, final_decision: str, invariant_hits: list[dict[str, Any]]) -> str:
    reasons = [str(code) for code in detail.decision.get("reason_codes", [])]
    action = str(detail.action.get("semantic_action") or detail.action_id)
    source_untrusted = (
        any(str(source.get("trust_level") or source.get("trust")) == "untrusted" for source in detail.sources)
        or "influenced_by_untrusted_source" in reasons
    )
    invariant_ids = [str(rule.get("rule_id") or rule.get("id")) for rule in invariant_hits]
    if final_decision == "block" and invariant_ids:
        prefix = "低可信来源诱导" if source_untrusted else "该动作"
        return f"{prefix}{action}，并触发不可降级安全不变量 {', '.join(invariant_ids)}，因此执行前阻断。"
    if final_decision == "block":
        return f"{action} 命中高风险策略条件，AgentBrake-Fusion 将多个证据合并后选择阻断。"
    if "sandbox" in final_decision:
        return f"{action} 仍有不确定风险，因此只能在沙箱或审批约束下继续。"
    if final_decision == "allow":
        return f"{action} 与任务边界和当前证据一致，未触发高危不变量。"
    return "该动作缺少完整判断轨迹，前端仅展示已有策略结论。"


def graph_for_run(events: list[StudioEvent], run_id: str) -> dict[str, Any]:
    run_events = [e for e in events if e.run_id == run_id]
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    for e in run_events:
        node_id = e.span_id
        nodes[node_id] = {"id": node_id, "type": e.type, "phase": e.phase, "severity": e.severity, "label": e.summary}
        for sid in e.payload.get("source_ids", []) or []:
            nodes.setdefault(str(sid), {"id": str(sid), "type": "source", "phase": "context", "severity": "info", "label": str(sid)})
            edges.append({"from": str(sid), "to": node_id, "relation": "influenced"})
        for ref in e.payload.get("evidence_refs", []) or []:
            nodes.setdefault(str(ref), {"id": str(ref), "type": "evidence", "phase": "evidence", "severity": "info", "label": str(ref)})
            edges.append({"from": str(ref), "to": node_id, "relation": "evidence"})
        if e.parent_span_id:
            edges.append({"from": e.parent_span_id, "to": node_id, "relation": "parent"})
    return {"nodes": list(nodes.values()), "edges": edges}


def _span_id(event_type: str, payload: dict[str, Any], event: dict[str, Any], index: int) -> str:
    if event_type == "policy_decision":
        return str(event.get("decision_id") or payload.get("decision_id") or event.get("event_id") or f"decision_{index}")
    if event_type == "policy_fact_set":
        return str(payload.get("fact_set_id") or event.get("event_id") or f"policy_fact_set_{index}")
    if event_type == "policy_eval_trace":
        return str(payload.get("policy_eval_trace_id") or event.get("event_id") or f"policy_eval_{index}")
    if event_type == "policy_runtime":
        return str(event.get("decision_id") or payload.get("decision_id") or event.get("event_id") or f"runtime_{index}")
    if event_type == "exec_trace":
        return str(payload.get("exec_trace_id") or event.get("event_id") or f"exec_{index}")
    if event_type == "package_event":
        return str(payload.get("package_event_id") or event.get("event_id") or f"package_{index}")
    if event_type == "secret_event":
        return str(payload.get("secret_event_id") or event.get("event_id") or f"secret_{index}")
    if event_type == "gateway_approval_request":
        return str(payload.get("approval_request_id") or event.get("event_id") or f"approval_{index}")
    if event_type == "action_graph":
        return str(payload.get("graph_id") or event.get("event_id") or f"action_graph_{index}")
    if event_type == "constraint_lattice_trace":
        return str(event.get("event_id") or f"constraint_lattice_{index}")
    if event_type == "session_state_update":
        return str(payload.get("session_state_id") or event.get("event_id") or f"session_state_{index}")
    return str(
        event.get("action_id")
        or payload.get("action_id")
        or event.get("decision_id")
        or payload.get("decision_id")
        or event.get("event_id")
        or f"event_{index}"
    )


def _payload_for_ui(event_type: str, payload: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    for key in ("action_id", "decision_id", "source_ids"):
        if event.get(key) and key not in out:
            out[key] = event[key]
    return out


def _parent_span(event_type: str, payload: dict[str, Any], event: dict[str, Any]) -> str | None:
    if event_type in {
        "policy_decision",
        "policy_fact_set",
        "policy_eval_trace",
        "policy_runtime",
        "exec_trace",
        "secret_event",
        "package_event",
    }:
        return str(event.get("action_id") or payload.get("action_id") or "") or None
    if event_type == "action_parsed":
        return str(payload.get("instruction_id") or payload.get("lowered_from_instruction_id") or "") or None
    return None


def _severity(event_type: str, payload: dict[str, Any]) -> str:
    decision = str(payload.get("decision") or payload.get("effective_decision") or "")
    semantic = str(payload.get("semantic_action") or "")
    risk = str(payload.get("risk") or "")
    if decision in {"block", "quarantine"} or risk == "critical" or semantic in DANGEROUS:
        return "critical"
    if decision in {"require_confirmation", "sandbox_then_approval", "allow_in_sandbox"} or risk == "high":
        return "warning"
    if event_type in {"gateway_response", "gateway_pre_call", "gateway_post_call"}:
        return "info"
    return "normal"


def _summary(event_type: str, payload: dict[str, Any]) -> str:
    if event_type == "policy_decision":
        return f"{payload.get('decision', 'decision')} {payload.get('semantic_action', payload.get('action_id', 'action'))}"
    if event_type == "policy_eval_trace":
        return f"policy trace {payload.get('final_decision', '')}"
    if event_type == "policy_runtime":
        return f"runtime {payload.get('effective_decision', '')}"
    if event_type == "action_parsed":
        return f"{payload.get('semantic_action', 'action')}: {payload.get('raw_action', '')}"[:180]
    if event_type == "source_ingested":
        return f"source {payload.get('source_id', '')} ({payload.get('source_type', '')})"
    if event_type == "instruction_ir":
        return f"instruction {payload.get('kind', payload.get('instruction_type', ''))}"
    if event_type == "gateway_response":
        return f"gateway response blocked={payload.get('blocked_count', 0)}"
    return event_type.replace("_", " ")
