"""Minimal local HTML dashboard renderer."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .audit import AuditLog


def render_dashboard(audit_path: str | Path, output_path: str | Path, approvals_path: str | Path | None = None) -> Path:
    audit = AuditLog(audit_path)
    events = audit.read_events()
    approvals = _read_jsonl(approvals_path) if approvals_path else []
    blocked = [
        e
        for e in events
        if e.get("event_type") == "policy_decision"
        and e.get("payload", {}).get("decision") in {"block", "quarantine", "require_confirmation", "sandbox_then_approval"}
    ]
    rows = []
    for event in blocked[-50:]:
        payload = event.get("payload", {})
        rows.append(
            "<tr>"
            f"<td>{html.escape(event.get('timestamp', ''))}</td>"
            f"<td>{html.escape(str(payload.get('decision', '')))}</td>"
            f"<td>{html.escape(str(payload.get('risk_score', '')))}</td>"
            f"<td>{html.escape(', '.join(payload.get('reason_codes', [])))}</td>"
            f"<td>{html.escape(_rule_label(payload))}</td>"
            f"<td>{html.escape(', '.join(str(x) for x in payload.get('evidence_refs', [])))}</td>"
            f"<td><code>{html.escape(str(event.get('action_id') or ''))}</code></td>"
            "</tr>"
        )
    chains = _evidence_chains(events)
    chain_rows = []
    for action_id, chain in list(chains.items())[-50:]:
        chain_rows.append(
            "<tr>"
            f"<td><code>{html.escape(action_id)}</code></td>"
            f"<td>{html.escape(', '.join(chain.get('sources', [])))}</td>"
            f"<td>{html.escape(', '.join(chain.get('rules', [])))}</td>"
            f"<td>{html.escape(', '.join(chain.get('decisions', [])))}</td>"
            "</tr>"
        )
    approval_rows = []
    for item in approvals[-50:]:
        payload = item.get("payload", {})
        approval_rows.append(
            "<tr>"
            f"<td>{html.escape(item.get('created_at', ''))}</td>"
            f"<td>{html.escape(item.get('event_type', ''))}</td>"
            f"<td>{html.escape(str(payload.get('approval_request_id') or payload.get('approval_id') or ''))}</td>"
            f"<td>{html.escape(str(payload.get('action_id') or ''))}</td>"
            "</tr>"
        )
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>AgentBrake-Fusion Dashboard</title>
<style>body{{font-family:system-ui;margin:32px;line-height:1.45}}.card{{border:1px solid #d0d7de;border-radius:8px;padding:16px;margin:16px 0}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{border:1px solid #d0d7de;padding:8px;vertical-align:top}}th{{background:#f6f8fa}}code{{background:#f6f8fa;padding:2px 4px;border-radius:4px}}</style>
</head><body>
<h1>AgentBrake-Fusion Dashboard</h1>
<div class="card"><strong>Audit:</strong> {html.escape(str(audit_path))}<br><strong>Events:</strong> {len(events)}<br><strong>Blocked / approval-required:</strong> {len(blocked)}</div>
<h2>Recent Policy Blocks</h2>
<table><thead><tr><th>time</th><th>decision</th><th>risk</th><th>reasons</th><th>rules</th><th>evidence</th><th>action</th></tr></thead><tbody>{"".join(rows)}</tbody></table>
<h2>Evidence Chains</h2>
<table><thead><tr><th>action</th><th>sources</th><th>rules</th><th>decisions</th></tr></thead><tbody>{"".join(chain_rows)}</tbody></table>
<h2>Approval Events</h2>
<table><thead><tr><th>time</th><th>type</th><th>approval</th><th>action</th></tr></thead><tbody>{"".join(approval_rows)}</tbody></table>
</body></html>"""
    out.write_text(doc, encoding="utf-8")
    return out


def _read_jsonl(path: str | Path | None) -> list[dict]:
    if not path or not Path(path).exists():
        return []
    rows = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _rule_label(payload: dict) -> str:
    rules = payload.get("matched_rules", []) or []
    return ", ".join(str(rule.get("rule_id") or rule.get("name") or "") for rule in rules)


def _evidence_chains(events: list[dict]) -> dict[str, dict[str, list[str]]]:
    chains: dict[str, dict[str, list[str]]] = {}
    for event in events:
        action_id = event.get("action_id")
        if not action_id:
            continue
        chain = chains.setdefault(str(action_id), {"sources": [], "rules": [], "decisions": []})
        for sid in event.get("source_ids", []) or []:
            if sid not in chain["sources"]:
                chain["sources"].append(str(sid))
        payload = event.get("payload", {})
        if event.get("event_type") == "policy_decision":
            for rule in payload.get("matched_rules", []) or []:
                rid = str(rule.get("rule_id") or rule.get("name") or "")
                if rid and rid not in chain["rules"]:
                    chain["rules"].append(rid)
            decision = str(payload.get("decision") or "")
            if decision and decision not in chain["decisions"]:
                chain["decisions"].append(decision)
        elif event.get("event_type") == "policy_eval_trace":
            for rid in payload.get("invariant_hits", []) or []:
                if rid and rid not in chain["rules"]:
                    chain["rules"].append(str(rid))
            decision = str(payload.get("final_decision") or "")
            if decision and decision not in chain["decisions"]:
                chain["decisions"].append(decision)
    return chains
