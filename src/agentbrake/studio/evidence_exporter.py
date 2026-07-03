"""Export redacted Studio evidence bundles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .event_stream import StudioEventIndex
from .redaction import redact_value


def export_evidence(index: StudioEventIndex, run_id: str, output_dir: str | Path) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    events = index.events(run_id=run_id, limit=10000)
    graph = index.graph(run_id)
    actions = [e for e in events if e.get("type") == "action_parsed"]
    decisions = [e for e in events if e.get("type") == "policy_decision"]
    policy_traces = [e for e in events if e.get("type") == "policy_eval_trace"]
    (out / "events.jsonl").write_text(
        "\n".join(json.dumps(redact_value(e), ensure_ascii=False, sort_keys=True) for e in events) + ("\n" if events else ""),
        encoding="utf-8",
    )
    (out / "actions.json").write_text(json.dumps(redact_value(actions), ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "decisions.json").write_text(json.dumps(redact_value(decisions), ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "policy_eval_traces.json").write_text(json.dumps(redact_value(policy_traces), ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "graph.json").write_text(json.dumps(redact_value(graph), ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "summary.md").write_text(_summary(run_id, events, decisions, policy_traces), encoding="utf-8")
    return out


def _summary(run_id: str, events: list[dict[str, Any]], decisions: list[dict[str, Any]], policy_traces: list[dict[str, Any]]) -> str:
    blocked = [
        d
        for d in decisions
        if d.get("payload", {}).get("decision") in {"block", "quarantine", "require_confirmation", "sandbox_then_approval"}
    ]
    lines = [
        f"# AgentBrake-Fusion Evidence Bundle: {run_id}",
        "",
        f"- Events: {len(events)}",
        f"- Policy decisions: {len(decisions)}",
        f"- Policy eval traces: {len(policy_traces)}",
        f"- Blocking decisions: {len(blocked)}",
        "",
        "## Decisions",
    ]
    for d in decisions:
        p = d.get("payload", {})
        lines.append(
            f"- `{p.get('decision')}` `{p.get('semantic_action', p.get('action_id', 'action'))}` reasons={p.get('reason_codes', [])}"
        )
    if policy_traces:
        lines.extend(["", "## MSJ Engine BrakeTrace"])
        for trace in policy_traces:
            p = trace.get("payload", {})
            lines.append(
                f"- `{p.get('final_decision')}` invariants={p.get('invariant_hits', [])} trace={p.get('policy_eval_trace_id', '')}"
            )
    return "\n".join(lines) + "\n"
