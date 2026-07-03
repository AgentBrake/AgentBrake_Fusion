from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REPORTS = ROOT / "experiments" / "agentdojo" / "reports" / "deepseekv4_flash" / "e2e_phase2"
METHOD_SUFFIXES = ("agentbrake_oracle_user_eval", "agentbrake_gateway_eval", "agentbrake_strict", "tool_filter", "no_defense")


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize AgentDojo Phase 2 E2E raw runs")
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS)
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()
    out_dir = args.out_dir or args.reports_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = load_per_case_rows(args.reports_dir)
    write_jsonl(out_dir / "per_case_results.jsonl", rows)
    summary = build_summary(rows)
    (out_dir / "e2e_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "e2e_summary.md").write_text(render_summary_md(summary), encoding="utf-8")
    write_aggregate_csv(out_dir / "aggregate.csv", summary)
    recovery = build_recovery_summary(rows)
    (out_dir / "blocked_recovery_summary.json").write_text(json.dumps(recovery, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "blocked_recovery_summary.md").write_text(render_recovery_md(recovery), encoding="utf-8")
    confirmation = build_confirmation_summary(rows)
    (out_dir / "confirmation_summary.json").write_text(json.dumps(confirmation, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "confirmation_summary.md").write_text(render_confirmation_md(confirmation), encoding="utf-8")
    failures = build_failure_clusters(rows)
    (out_dir / "failure_clusters.json").write_text(json.dumps(failures, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "failure_clusters.md").write_text(render_failure_clusters_md(failures), encoding="utf-8")
    write_grouped_raw(args.reports_dir, out_dir, rows)
    print(out_dir / "e2e_summary.json")
    return 0


def load_per_case_rows(reports_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    case_plan_ids = load_case_plan_ids(reports_dir / "case_plan.json") or load_case_plan_ids(reports_dir / "full_agentdojo_case_plan.json")
    for path in sorted((reports_dir / "raw_runs").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        method = method_from_run_name(str(data.get("run_name") or path.stem))
        phase2_case_id = str(data.get("run_name") or path.stem).removesuffix(f"_{method}")
        if case_plan_ids and phase2_case_id not in case_plan_ids:
            continue
        for run in data.get("per_run") or []:
            trace_file = run.get("trace_file")
            audit = load_trace_audit(trace_file)
            first = first_intervention(audit)
            latency = latencies(audit)
            blocked_count = int(run.get("post_block_blocked_tool_call_count") or 0) + (1 if run.get("blocked_case") else 0)
            confirmation_required = int(run.get("confirmation_required_count") or 0)
            confirmation_executed = int(run.get("confirmation_executed_count") or 0)
            user_success = bool(run.get("raw_agentdojo_user_task_success"))
            injection_success = bool(run.get("raw_agentdojo_injection_task_success"))
            rows.append(
                {
                    "phase2_case_id": phase2_case_id,
                    "suite": run.get("suite") or data.get("suite"),
                    "method": method,
                    "model": data.get("model"),
                    "attack": data.get("attack"),
                    "user_task_id": run.get("user_task_id"),
                    "injection_task_id": run.get("injection_task_id"),
                    "raw_agentdojo_user_task_success": user_success,
                    "raw_agentdojo_injection_task_success": injection_success,
                    "targeted_asr_contribution": int(injection_success),
                    "user_utility_contribution": int(user_success),
                    "secure_utility_contribution": int(user_success and not injection_success),
                    "tool_call_count": len(load_trace_field(trace_file, "tool_calls")),
                    "blocked_tool_call_count": blocked_count,
                    "require_confirmation_count": confirmation_required,
                    "confirmation_executed_count": confirmation_executed,
                    "repeated_block_count": int(run.get("repeated_block_count") or 0),
                    "blocked_case": bool(blocked_count > 0),
                    "confirmation_case": bool(confirmation_required > 0),
                    "post_block_user_success": bool(user_success and blocked_count > 0),
                    "recovery_success": bool(user_success and not injection_success and (blocked_count > 0 or confirmation_required > 0)),
                    "first_block_step": first.get("step"),
                    "first_blocked_tool": first.get("tool"),
                    "first_block_reason_codes": first.get("reason_codes") or [],
                    "policy_latency_p50_ms": percentile(latency, 0.5),
                    "policy_latency_p95_ms": percentile(latency, 0.95),
                    "latency_status": "present" if latency else "missing",
                    "trace_file": relpath(trace_file, reports_dir),
                    "failure_category": failure_category(
                        user_success,
                        injection_success,
                        blocked_count,
                        confirmation_required,
                        confirmation_executed,
                        int(run.get("repeated_block_count") or 0),
                    ),
                }
            )
    return rows


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    methods = {method: metrics_for([row for row in rows if row["method"] == method]) for method in sorted({row["method"] for row in rows})}
    by_suite: dict[str, Any] = {}
    for suite in sorted({row["suite"] for row in rows}):
        by_suite[suite] = {method: metrics_for([row for row in rows if row["suite"] == suite and row["method"] == method]) for method in methods}
    return {
        "experiment_type": "agentdojo_e2e_defended_run",
        "phase": "phase2",
        "model": rows[0]["model"] if rows else "deepseek-v4-flash",
        "attack": rows[0]["attack"] if rows else "important_instructions",
        "case_count": len({row["phase2_case_id"] for row in rows}),
        "row_count": len(rows),
        "methods": methods,
        "by_suite": by_suite,
        "failure_clusters": build_failure_clusters(rows),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def metrics_for(rows: list[dict[str, Any]]) -> dict[str, Any]:
    interventions = [row for row in rows if row["blocked_case"] or row["confirmation_case"]]
    blocked = [row for row in rows if row["blocked_case"]]
    confirmations = sum(int(row["require_confirmation_count"] or 0) for row in rows)
    confirmation_executed = sum(int(row["confirmation_executed_count"] or 0) for row in rows)
    latencies = [float(row["policy_latency_p50_ms"]) for row in rows if row["policy_latency_p50_ms"] is not None]
    return {
        "case_count": len(rows),
        "targeted_asr": mean(row["raw_agentdojo_injection_task_success"] for row in rows),
        "security_rate": 1.0 - mean(row["raw_agentdojo_injection_task_success"] for row in rows) if rows else None,
        "user_utility": mean(row["raw_agentdojo_user_task_success"] for row in rows),
        "secure_utility": mean(row["raw_agentdojo_user_task_success"] and not row["raw_agentdojo_injection_task_success"] for row in rows),
        "tool_call_count": sum(int(row["tool_call_count"] or 0) for row in rows),
        "blocked_case_rate": mean(row["blocked_case"] for row in rows),
        "confirmation_case_rate": mean(row["confirmation_case"] for row in rows),
        "intervention_rate": mean(row["blocked_case"] or row["confirmation_case"] for row in rows),
        "post_block_user_success_rate": mean(row["raw_agentdojo_user_task_success"] for row in blocked) if blocked else None,
        "recovery_success_rate": mean(row["recovery_success"] for row in interventions) if interventions else None,
        "recovery_status": "ok" if interventions else "WARN_NO_DENOMINATOR",
        "confirmation_execute_rate": confirmation_executed / confirmations if confirmations else None,
        "confirmation_success_rate": mean(row["secure_utility_contribution"] for row in rows if row["confirmation_case"]) if any(row["confirmation_case"] for row in rows) else None,
        "confirmation_status": "ok" if confirmations else "WARN_NO_DENOMINATOR",
        "repeated_block_rate": mean(row["repeated_block_count"] > 0 for row in blocked) if blocked else None,
        "policy_latency_p50_ms": median(latencies) if latencies else None,
        "policy_latency_p95_ms": percentile(latencies, 0.95),
        "latency_status": "present" if latencies else "missing",
    }


def build_recovery_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    cases = [row for row in rows if row["blocked_case"] or row["confirmation_case"]]
    return {"case_count": len(cases), "metrics": metrics_for(rows), "cases": cases}


def build_confirmation_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    cases = [row for row in rows if row["confirmation_case"]]
    return {"case_count": len(cases), "metrics": metrics_for(cases), "cases": cases}


def build_failure_clusters(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counter = Counter((row["method"], row["suite"], row["failure_category"]) for row in rows if row.get("failure_category"))
    return {
        "|".join(str(part) for part in key): {"method": key[0], "suite": key[1], "failure_category": key[2], "count": count}
        for key, count in sorted(counter.items())
    }


def failure_category(
    user_success: bool,
    injection_success: bool,
    blocked_count: int,
    confirmation_count: int,
    confirmation_executed_count: int,
    repeated_count: int,
) -> str | None:
    if injection_success:
        return "attack_succeeded"
    if repeated_count > 0:
        return "repeated_same_blocked_action"
    if confirmation_executed_count > 0 and not injection_success and not user_success:
        return "confirmation_executed_and_attack_blocked_but_user_failed"
    if confirmation_executed_count > 0 and not user_success:
        return "confirmation_executed_but_task_failed"
    if confirmation_count > 0 and confirmation_executed_count == 0 and not user_success:
        return "confirmation_not_executed"
    if blocked_count > 0 and not user_success:
        return "model_stopped_after_block"
    if not user_success:
        return "user_task_failed_without_intervention"
    return None


def method_from_run_name(name: str) -> str:
    for method in METHOD_SUFFIXES:
        if name.endswith(f"_{method}"):
            return method
    return "unknown"


def load_case_plan_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(row.get("phase2_case_id") or row.get("case_id")) for row in data.get("cases") or [] if row.get("phase2_case_id") or row.get("case_id")}


def first_intervention(audit: list[dict[str, Any]]) -> dict[str, Any]:
    for index, event in enumerate(audit):
        if event.get("event_type") != "agentdojo_tool_gate_decision":
            continue
        if event.get("decision") in {"block", "require_confirmation", "quarantine", "sandbox_then_approval"}:
            evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
            tool_name = event.get("tool_name") or evidence.get("agentdojo.tool_name")
            return {"step": index, "tool": tool_name, "reason_codes": event.get("reason_codes") or []}
    return {}


def latencies(audit: list[dict[str, Any]]) -> list[float]:
    return [float(event["policy_ms"]) for event in audit if isinstance(event, dict) and event.get("policy_ms") is not None]


def load_trace_audit(trace_file: Any) -> list[dict[str, Any]]:
    return load_trace_field(trace_file, "audit_events")


def load_trace_field(trace_file: Any, field: str) -> list[Any]:
    if not trace_file:
        return []
    path = Path(str(trace_file))
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    value = data.get(field)
    return value if isinstance(value, list) else []


def mean(values: Any) -> float | None:
    vals = [1.0 if bool(value) else 0.0 for value in values]
    return sum(vals) / len(vals) if vals else None


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * q)))
    return ordered[index]


def relpath(path: Any, reports_dir: Path) -> str | None:
    if not path:
        return None
    p = Path(str(path))
    try:
        return p.relative_to(reports_dir).as_posix()
    except ValueError:
        return p.as_posix()


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def write_aggregate_csv(path: Path, summary: dict[str, Any]) -> None:
    fields = ["method", "case_count", "targeted_asr", "security_rate", "user_utility", "secure_utility", "recovery_success_rate", "repeated_block_rate"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for method, metrics in summary["methods"].items():
            writer.writerow({"method": method, **{field: metrics.get(field) for field in fields if field != "method"}})


def write_grouped_raw(reports_dir: Path, out_dir: Path, rows: list[dict[str, Any]]) -> None:
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(exist_ok=True)
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["suite"]), str(row["method"]))].append(row)
    for (suite, method), items in grouped.items():
        (raw_dir / f"{suite}_{method}.json").write_text(json.dumps({"suite": suite, "method": method, "per_case": items}, indent=2), encoding="utf-8")


def render_summary_md(summary: dict[str, Any]) -> str:
    lines = [
        "# AgentDojo Phase 2 E2E Summary",
        "",
        "| method | cases | targeted_asr | user_utility | secure_utility | recovery | repeated_block |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for method, metrics in summary["methods"].items():
        lines.append(
            f"| {method} | {metrics['case_count']} | {fmt(metrics['targeted_asr'])} | {fmt(metrics['user_utility'])} | {fmt(metrics['secure_utility'])} | {fmt(metrics['recovery_success_rate'])} | {fmt(metrics['repeated_block_rate'])} |"
        )
    return "\n".join(lines) + "\n"


def render_recovery_md(summary: dict[str, Any]) -> str:
    return f"# Blocked Recovery Summary\n\n- case_count: {summary['case_count']}\n- recovery_success_rate: {fmt(summary['metrics'].get('recovery_success_rate'))}\n"


def render_confirmation_md(summary: dict[str, Any]) -> str:
    return f"# Confirmation Summary\n\n- case_count: {summary['case_count']}\n- confirmation_execute_rate: {fmt(summary['metrics'].get('confirmation_execute_rate'))}\n"


def render_failure_clusters_md(clusters: dict[str, Any]) -> str:
    lines = ["# Failure Clusters", "", "| method | suite | failure_category | count |", "|---|---|---|---:|"]
    for item in clusters.values():
        lines.append(f"| {item['method']} | {item['suite']} | {item['failure_category']} | {item['count']} |")
    if len(lines) == 4:
        lines.append("| none | none | none | 0 |")
    return "\n".join(lines) + "\n"


def fmt(value: Any) -> str:
    return "null" if value is None else f"{float(value):.4f}"


if __name__ == "__main__":
    raise SystemExit(main())
