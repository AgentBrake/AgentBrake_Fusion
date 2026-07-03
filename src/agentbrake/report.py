"""HTML report generation for audit incidents and bench suites."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .audit import AuditLog


def render_incident_html(audit_path: str | Path, output_path: str | Path) -> Path:
    audit = AuditLog(audit_path)
    events = audit.read_events()
    ok, errors = audit.verify()
    graph = audit.incident_graph()
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for ev in events:
        payload = ev.get("payload", {})
        rows.append(
            "<tr>"
            f"<td>{html.escape(ev.get('timestamp', ''))}</td>"
            f"<td>{html.escape(ev.get('event_type', ''))}</td>"
            f"<td>{html.escape(ev.get('actor', ''))}</td>"
            f"<td><code>{html.escape(ev.get('action_id') or '')}</code></td>"
            f"<td>{html.escape(_compact_payload(payload))}</td>"
            "</tr>"
        )
    chain = _chain_summary(events)
    doc = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>AgentBrake-Fusion Incident Report</title>
<style>body{{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:32px;line-height:1.45}}code,pre{{background:#f6f8fa;border-radius:6px;padding:2px 4px}}.card{{border:1px solid #d0d7de;border-radius:10px;padding:16px;margin:16px 0}}.ok{{color:#116329;font-weight:700}}.bad{{color:#cf222e;font-weight:700}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{border:1px solid #d0d7de;padding:8px;vertical-align:top}}th{{background:#f6f8fa}}.node{{display:inline-block;border:1px solid #d0d7de;border-radius:8px;padding:6px 8px;margin:4px;background:#f6f8fa}}</style>
</head><body><h1>AgentBrake-Fusion 事件审计报告</h1>
<div class="card"><p>Hash-chain 验证：<span class="{"ok" if ok else "bad"}">{"通过" if ok else "失败"}</span></p><p>事件数：{len(events)}，图节点数：{len(graph.get("nodes", []))}，hash head：<code>{html.escape(audit.head)}</code></p>{("<p>错误：" + html.escape("; ".join(errors)) + "</p>") if errors else ""}</div>
<div class="card"><h2>攻击链摘要</h2>{chain}</div>
<div class="card"><h2>Incident Graph 节点</h2>{"".join('<span class="node">' + html.escape(n.get("type", "")) + ": " + html.escape(n.get("label", n.get("id", ""))) + "</span>" for n in graph.get("nodes", [])[:120])}</div>
<h2>事件时间线</h2><table><thead><tr><th>时间</th><th>事件</th><th>actor</th><th>action</th><th>payload 摘要</th></tr></thead><tbody>{"".join(rows)}</tbody></table>
</body></html>"""
    output.write_text(doc, encoding="utf-8")
    return output


def render_suite_html(report_json: str | Path, output_path: str | Path) -> Path:
    report = json.loads(Path(report_json).read_text(encoding="utf-8"))
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for item in report.get("samples", []):
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('sample_id', '')))}</td>"
            f"<td>{'✅' if item.get('utility_ok') else '❌'}</td>"
            f"<td>{'✅' if item.get('security_ok') else '❌'}</td>"
            f"<td>{'✅' if item.get('evidence_complete') else '❌'}</td>"
            f"<td>{html.escape(str(item.get('dangerous_action_requested')))}</td>"
            f"<td>{html.escape(str(item.get('dangerous_action_executed')))}</td>"
            "</tr>"
        )
    metrics = report.get("metrics", {})
    metric_cards = "".join(
        "<div class='metric'><strong>" + html.escape(str(key)) + "</strong><span>" + html.escape(str(value)) + "</span></div>"
        for key, value in metrics.items()
    )
    doc = f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>AgentBrake-Fusion Bench Suite</title>
<style>body{{font-family:system-ui;margin:32px}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #d0d7de;padding:8px}}th{{background:#f6f8fa}}.card{{border:1px solid #d0d7de;border-radius:10px;padding:16px;margin:16px 0}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:16px 0}}.metric{{border:1px solid #d0d7de;border-radius:8px;padding:12px;background:#f6f8fa}}.metric strong{{display:block;font-size:13px;color:#57606a}}.metric span{{font-size:20px;font-weight:700}}</style>
</head><body><h1>AgentBrake-Fusion AgentTool-SecBench 报告</h1><div class="card"><pre>{html.escape(json.dumps(metrics, ensure_ascii=False, indent=2))}</pre></div><table><thead><tr><th>sample</th><th>utility</th><th>security</th><th>evidence</th><th>danger requested</th><th>danger executed</th></tr></thead><tbody>{"".join(rows)}</tbody></table></body></html>"""
    doc = doc.replace('<div class="card"><pre>', f'<div class="metrics">{metric_cards}</div><div class="card"><pre>', 1)
    output.write_text(doc, encoding="utf-8")
    return output


def _compact_payload(payload: dict[str, Any]) -> str:
    keys = ["decision", "semantic_action", "reason_codes", "risk_score", "source_type", "sandbox_profile", "risk_observed"]
    compact = {k: payload.get(k) for k in keys if k in payload}
    if not compact:
        compact = {k: payload.get(k) for k in list(payload)[:4]} if isinstance(payload, dict) else {"value": str(payload)}
    return json.dumps(compact, ensure_ascii=False)[:500]


def _chain_summary(events: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for typ in ["source_ingested", "agent_plan", "action_parsed", "package_event", "exec_trace", "secret_event", "policy_decision"]:
        ev = next((e for e in events if e.get("event_type") == typ), None)
        if ev:
            payload = ev.get("payload", {})
            label = payload.get("semantic_action") or payload.get("decision") or payload.get("source_type") or typ
            parts.append(f"<span class='node'>{html.escape(typ)}: {html.escape(str(label))}</span>")
    return " → ".join(parts) if parts else "<p>未发现完整攻击链事件。</p>"
