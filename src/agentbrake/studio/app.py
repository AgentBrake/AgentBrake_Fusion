"""AgentBrake-Fusion Studio: lightweight HTML observability dashboard."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from ..approval_api import approval_events_summary
from ..approvals import ApprovalStore
from ..audit import AuditLog


def render_studio_html(
    audit_path: str | Path,
    output_path: str | Path,
    bench_report: str | Path | None = None,
    trace_matrix_report: str | Path | None = None,
    approvals_path: str | Path | None = None,
    title: str = "AgentBrake-Fusion Studio Pro",
) -> Path:
    audit = AuditLog(audit_path)
    events = audit.read_events()
    ok, errors = audit.verify()
    graph = audit.incident_graph()
    bench = _load_json(bench_report) if bench_report else None
    trace_matrix = _load_json(trace_matrix_report) if trace_matrix_report else None
    approvals = approval_events_summary(ApprovalStore(approvals_path)) if approvals_path else None
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    policy_hits = [
        e for e in events if e.get("event_type") in {"policy_decision", "policy_fact_set", "policy_eval_trace", "policy_runtime"}
    ]
    instructions = [e for e in events if e.get("event_type") == "instruction_ir"]
    traces = [
        e
        for e in events
        if e.get("event_type")
        in {
            "gateway_pre_call",
            "gateway_post_call",
            "gateway_response",
            "instruction_ir",
            "action_parsed",
            "exec_trace",
            "policy_decision",
            "policy_fact_set",
            "policy_eval_trace",
            "policy_runtime",
        }
    ]

    html_doc = f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
body{{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:32px;line-height:1.45;color:#24292f}}
.card{{border:1px solid #d0d7de;border-radius:12px;padding:16px;margin:16px 0;background:#fff}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}}
.metric{{border:1px solid #d0d7de;border-radius:10px;padding:12px;background:#f6f8fa}}
.metric b{{font-size:24px}}
.ok{{color:#116329;font-weight:700}}.bad{{color:#cf222e;font-weight:700}}
.node{{display:inline-block;border:1px solid #d0d7de;border-radius:8px;padding:6px 8px;margin:4px;background:#f6f8fa}}
pre{{white-space:pre-wrap;background:#f6f8fa;border-radius:8px;padding:12px;overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{border:1px solid #d0d7de;padding:8px;vertical-align:top}}th{{background:#f6f8fa}}
</style></head><body>
<h1>{html.escape(title)}</h1>
<div class="grid">
  <div class="metric">Hash-chain<br><b class="{"ok" if ok else "bad"}">{"OK" if ok else "FAIL"}</b></div>
  <div class="metric">Events<br><b>{len(events)}</b></div>
  <div class="metric">Instructions<br><b>{len(instructions)}</b></div>
  <div class="metric">Policy hits<br><b>{len(policy_hits)}</b></div>
  <div class="metric">Approvals<br><b>{approvals.get("metrics", {}).get("requests", 0) if approvals else 0}</b></div>
</div>
{('<div class="card bad">' + html.escape("; ".join(errors)) + "</div>") if errors else ""}
<div class="card"><h2>Trace</h2>{_event_table(traces)}</div>
<div class="card"><h2>Incident Graph</h2>{"".join('<span class="node">' + html.escape(n.get("type", "")) + ": " + html.escape(n.get("label", n.get("id", ""))) + "</span>" for n in graph.get("nodes", [])[:160])}</div>
<div class="card"><h2>Policy</h2>{_event_table(policy_hits)}</div>
<div class="card"><h2>Approvals</h2>{_approval_block(approvals)}</div>
<div class="card"><h2>Trace Matrix</h2>{_trace_matrix_block(trace_matrix)}</div>
<div class="card"><h2>Bench</h2>{_bench_block(bench)}</div>
</body></html>"""
    output.write_text(html_doc, encoding="utf-8")
    return output


def _event_table(events: list[dict[str, Any]]) -> str:
    rows = []
    for e in events[:300]:
        payload = e.get("payload", {})
        rows.append(
            "<tr>"
            + f"<td>{html.escape(e.get('timestamp', ''))}</td>"
            + f"<td>{html.escape(e.get('event_type', ''))}</td>"
            + f"<td>{html.escape(e.get('actor', ''))}</td>"
            + f"<td>{html.escape(str(e.get('action_id') or ''))}</td>"
            + f"<td><pre>{html.escape(json.dumps(_compact(payload), ensure_ascii=False, indent=2))}</pre></td>"
            + "</tr>"
        )
    return (
        "<table><thead><tr><th>time</th><th>event</th><th>actor</th><th>action</th><th>payload</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _compact(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    keys = [
        "trace_id",
        "turn_id",
        "kind",
        "instruction_type",
        "instruction_category",
        "semantic_action",
        "raw_action",
        "fact_set_id",
        "fact_count",
        "decision",
        "final_decision",
        "risk_score",
        "reason_codes",
        "invariant_hits",
        "effective_decision",
        "mode",
        "warning",
        "blocked_count",
    ]
    out = {k: payload[k] for k in keys if k in payload}
    if not out and "security_type" in payload:
        out = {
            "instruction_id": payload.get("instruction_id"),
            "kind": payload.get("kind"),
            "security_type": payload.get("security_type"),
            "metadata": payload.get("metadata"),
        }
    if not out:
        out = {k: payload.get(k) for k in list(payload)[:6]}
    return out


def _bench_block(bench: dict[str, Any] | None) -> str:
    if not bench:
        return "<p>未附加 bench report。</p>"
    return "<pre>" + html.escape(json.dumps(bench.get("metrics", bench), ensure_ascii=False, indent=2)) + "</pre>"


def _approval_block(approvals: dict[str, Any] | None) -> str:
    if not approvals:
        return "<p>No approval store loaded.</p>"
    return (
        "<pre>"
        + html.escape(json.dumps(approvals.get("metrics", approvals), ensure_ascii=False, indent=2))
        + "</pre>"
        + _event_table(approvals.get("events", []))
    )


def _trace_matrix_block(report: dict[str, Any] | None) -> str:
    if not report:
        return "<p>No trace matrix report loaded.</p>"
    rows = []
    for row in report.get("rows", [])[:200]:
        rows.append(
            "<tr>"
            f"<td>{html.escape('PASS' if row.get('ok') else 'FAIL')}</td>"
            f"<td>{html.escape(str(row.get('agent_type', '')))}</td>"
            f"<td>{html.escape(str(row.get('canonical_tool', '')))}</td>"
            f"<td>{html.escape(str(row.get('semantic_action', '')))}</td>"
            f"<td>{html.escape(str(row.get('raw_action', '')))}</td>"
            "</tr>"
        )
    return (
        "<pre>"
        + html.escape(json.dumps(report.get("metrics", report), ensure_ascii=False, indent=2))
        + "</pre>"
        + "<table><thead><tr><th>status</th><th>agent</th><th>tool</th><th>semantic action</th><th>raw action</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _load_json(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))
