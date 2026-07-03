"""Agent trace compatibility matrix for parser/schema drift experiments."""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .instruction_ir import InstructionBuilder, InstructionLowerer
from .plugins import ToolParserRegistry


def load_trace_events(trace_root: str | Path) -> list[dict[str, Any]]:
    root = Path(trace_root)
    paths = [root] if root.is_file() else sorted(root.glob("*.jsonl"))
    events: list[dict[str, Any]] = []
    for path in paths:
        for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            event.setdefault("trace_file", path.name)
            event.setdefault("line", idx)
            events.append(event)
    return events


def run_trace_matrix(trace_root: str | Path, output_dir: str | Path | None = None) -> dict[str, Any]:
    events = load_trace_events(trace_root)
    registry = ToolParserRegistry()
    lowerer = InstructionLowerer()
    rows: list[dict[str, Any]] = []

    for event in events:
        expected = event.get("expected") or {}
        row = {
            "trace_file": event.get("trace_file"),
            "line": event.get("line"),
            "trace_id": event.get("trace_id"),
            "agent_type": event.get("agent_type", "generic_json"),
            "ok": False,
            "errors": [],
        }
        try:
            builder = InstructionBuilder(trace_id=str(event.get("trace_id") or "trace_matrix"), registry=registry)
            instruction = builder.from_tool_call(
                event["tool_call"],
                turn_id=str(event.get("turn_id") or "turn_1"),
                source_ids=list(event.get("source_ids") or []),
                agent_type=str(event.get("agent_type") or "generic_json"),
                trust_floor=str(event.get("trust_floor") or "untrusted"),  # type: ignore[arg-type]
            )
            action = lowerer.lower(instruction, cwd=Path("."))
            parsed = instruction.metadata.get("tool_parse", {})
            row.update(
                {
                    "canonical_tool": instruction.metadata.get("canonical_tool"),
                    "parser_confidence": instruction.parser_confidence,
                    "instruction_type": instruction.instruction_type,
                    "instruction_category": instruction.instruction_category,
                    "semantic_action": action.semantic_action if action else None,
                    "raw_action": action.raw_action if action else None,
                    "action": asdict(action) if action else None,
                    "parsed": parsed,
                }
            )
            if not action:
                row["errors"].append("not_lowered")
            for key in ["canonical_tool", "semantic_action", "raw_action"]:
                if key in expected and row.get(key) != expected[key]:
                    row["errors"].append(f"{key}: expected {expected[key]!r}, got {row.get(key)!r}")
            row["ok"] = not row["errors"]
        except Exception as exc:  # pragma: no cover - defensive reporting
            row["errors"].append(f"{type(exc).__name__}: {exc}")
        rows.append(row)

    by_agent: dict[str, dict[str, Any]] = {}
    for row in rows:
        agent = str(row["agent_type"])
        bucket = by_agent.setdefault(
            agent, {"agent_type": agent, "count": 0, "passed": 0, "failed": 0, "parse_coverage": 0.0, "semantic_accuracy": 0.0}
        )
        bucket["count"] += 1
        if row["ok"]:
            bucket["passed"] += 1
        else:
            bucket["failed"] += 1

    for bucket in by_agent.values():
        count = max(int(bucket["count"]), 1)
        agent_rows = [r for r in rows if r["agent_type"] == bucket["agent_type"]]
        parsed = sum(1 for r in agent_rows if r.get("canonical_tool") and r.get("parser_confidence", 0) >= 0.5)
        semantic_ok = sum(1 for r in agent_rows if not any(str(e).startswith("semantic_action:") for e in r.get("errors", [])))
        bucket["parse_coverage"] = round(parsed / count, 3)
        bucket["semantic_accuracy"] = round(semantic_ok / count, 3)

    report = {
        "metrics": {
            "trace_count": len(rows),
            "agent_count": len(by_agent),
            "pass_rate": round(sum(1 for r in rows if r["ok"]) / max(len(rows), 1), 3),
            "parse_coverage": round(
                sum(1 for r in rows if r.get("canonical_tool") and r.get("parser_confidence", 0) >= 0.5) / max(len(rows), 1), 3
            ),
        },
        "by_agent": sorted(by_agent.values(), key=lambda x: x["agent_type"]),
        "rows": rows,
    }
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "trace_matrix_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        render_trace_matrix_html(report, out / "trace_matrix_report.html")
    return report


def render_trace_matrix_html(report: dict[str, Any], output_path: str | Path) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for row in report.get("rows", []):
        status = "PASS" if row.get("ok") else "FAIL"
        rows.append(
            "<tr>"
            f"<td>{html.escape(status)}</td>"
            f"<td>{html.escape(str(row.get('agent_type', '')))}</td>"
            f"<td>{html.escape(str(row.get('canonical_tool', '')))}</td>"
            f"<td>{html.escape(str(row.get('semantic_action', '')))}</td>"
            f"<td>{html.escape(str(row.get('raw_action', '')))}</td>"
            f"<td>{html.escape('; '.join(row.get('errors') or []))}</td>"
            "</tr>"
        )
    body = f"""<!doctype html><html><head><meta charset="utf-8"><title>AgentBrake-Fusion Trace Matrix</title>
<style>body{{font-family:system-ui;margin:32px;color:#24292f}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #d0d7de;padding:8px;vertical-align:top}}th{{background:#f6f8fa}}.metric{{display:inline-block;border:1px solid #d0d7de;padding:12px;margin:6px;border-radius:8px}}</style></head><body>
<h1>AgentBrake-Fusion Agent Trace Compatibility Matrix</h1>
<div class="metric">traces: <b>{report.get("metrics", {}).get("trace_count", 0)}</b></div>
<div class="metric">agents: <b>{report.get("metrics", {}).get("agent_count", 0)}</b></div>
<div class="metric">pass rate: <b>{report.get("metrics", {}).get("pass_rate", 0)}</b></div>
<div class="metric">parse coverage: <b>{report.get("metrics", {}).get("parse_coverage", 0)}</b></div>
<h2>By Agent</h2><pre>{html.escape(json.dumps(report.get("by_agent", []), ensure_ascii=False, indent=2))}</pre>
<h2>Rows</h2><table><thead><tr><th>status</th><th>agent</th><th>canonical tool</th><th>semantic action</th><th>raw action</th><th>errors</th></tr></thead><tbody>{"".join(rows)}</tbody></table>
</body></html>"""
    output.write_text(body, encoding="utf-8")
    return output
