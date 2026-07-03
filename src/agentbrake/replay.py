"""Replay-bundle validation."""

from __future__ import annotations

from pathlib import Path

from .audit import AuditLog


def verify_bundle(bundle_dir: str | Path) -> tuple[bool, list[str]]:
    bundle = Path(bundle_dir)
    log = bundle / "audit.jsonl"
    if not log.exists():
        return False, ["audit.jsonl missing"]
    audit = AuditLog(log)
    ok, errors = audit.verify()
    if not (bundle / "replay_spec.json").exists():
        errors.append("replay_spec.json missing")
    if not (bundle / "incident_graph.json").exists():
        errors.append("incident_graph.json missing")
    errors.extend(_verify_policy_replay_inputs(audit))
    return ok and not errors, errors


def _verify_policy_replay_inputs(audit: AuditLog) -> list[str]:
    errors: list[str] = []
    actions: dict[str, dict] = {}
    exec_traces: set[str] = set()
    package_events: set[str] = set()
    for event in audit.read_events():
        payload = event.get("payload", {})
        if event.get("event_type") == "action_parsed" and event.get("action_id"):
            actions[str(event["action_id"])] = payload
        elif event.get("event_type") == "exec_trace":
            if payload.get("exec_trace_id"):
                exec_traces.add(str(payload["exec_trace_id"]))
        elif event.get("event_type") == "package_event":
            if payload.get("package_event_id"):
                package_events.add(str(payload["package_event_id"]))
        elif event.get("event_type") == "policy_decision":
            action_id = str(event.get("action_id") or payload.get("action_id") or "")
            if action_id and action_id not in actions:
                errors.append(f"policy_decision references missing action: {action_id}")
            if not payload.get("policy_version"):
                errors.append(f"policy_decision missing policy_version: {event.get('event_id')}")
            if not payload.get("matched_rules"):
                errors.append(f"policy_decision missing matched_rules: {event.get('event_id')}")
            exec_trace_id = payload.get("exec_trace_id")
            if exec_trace_id and str(exec_trace_id) not in exec_traces:
                errors.append(f"policy_decision references missing exec_trace: {exec_trace_id}")
            package_event_id = payload.get("package_event_id")
            if package_event_id and str(package_event_id) not in package_events:
                errors.append(f"policy_decision references missing package_event: {package_event_id}")
    return errors
