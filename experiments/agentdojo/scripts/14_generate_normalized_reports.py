from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, NamedTuple

from agentbrake.eval.agentdojo.runner.metrics import (
    METRIC_SCHEMA_VERSION,
    compute_agentdojo_metrics,
    normalize_raw_agentdojo_result,
)

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REPORTS = ROOT / "experiments" / "agentdojo" / "reports"
DEFAULT_OUT = DEFAULT_REPORTS / "normalized"


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate normalized AgentDojo reports without modifying raw logs")
    parser.add_argument("--reports-dir", "--input", dest="reports_dir", type=Path, default=DEFAULT_REPORTS)
    parser.add_argument("--out-dir", "--output", dest="out_dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--method", "--defense", dest="method", default=None)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    cases, run_aggregates = collect_report_data(args.reports_dir, method_filter=args.method)
    metrics = compute_agentdojo_metrics(cases)
    normalized_rows = [case.as_normalized_dict() for case in cases]

    (args.out_dir / "per_case_normalized.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in normalized_rows) + ("\n" if normalized_rows else ""),
        encoding="utf-8",
    )
    (args.out_dir / "corrected_metrics.json").write_text(
        json.dumps({**metrics, "case_count": len(cases)}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (args.out_dir / "corrected_summary.md").write_text(render_summary(metrics, normalized_rows), encoding="utf-8")
    (args.out_dir / "deprecated_report_mapping.md").write_text(render_deprecated_mapping(), encoding="utf-8")
    aggregate = aggregate_rows(normalized_rows, run_aggregates)
    write_csv(args.out_dir / "aggregate.csv", aggregate)
    write_csv(args.out_dir / "leaderboard.csv", leaderboard_rows(aggregate))
    ensure_metric_schema(args.out_dir)
    print(args.out_dir / "corrected_summary.md")
    return 0


class RunAggregate(NamedTuple):
    suite: str
    method: str
    run_id: str
    tool_call_count: int = 0
    blocked_tool_call_count: int = 0
    repeated_block_count: int = 0
    policy_latency_p50_ms: float = 0.0
    policy_latency_p95_ms: float = 0.0


def collect_cases(reports_dir: Path, *, method_filter: str | None = None) -> list[Any]:
    cases, _aggregates = collect_report_data(reports_dir, method_filter=method_filter)
    return cases


def collect_report_data(reports_dir: Path, *, method_filter: str | None = None) -> tuple[list[Any], list[RunAggregate]]:
    cases = []
    run_aggregates: list[RunAggregate] = []
    for path in sorted(reports_dir.rglob("*.json")):
        if "normalized" in path.parts:
            continue
        if "confirmation_modes" in path.parts and "confirmation_modes" not in reports_dir.parts:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        if not looks_like_summary(data):
            continue
        audit = data.get("agentdojo_firewall_audit_summary") or data.get("agentbrake_audit_summary") or {}
        summary_method = data.get("defense")
        if method_filter is None or str(summary_method) == str(method_filter):
            run_aggregates.append(
                RunAggregate(
                    suite=str(data.get("suite") or "unknown"),
                    method=str(summary_method or "unknown"),
                    run_id=str(data.get("run_name") or path.stem),
                    tool_call_count=int(
                        audit.get("total_tool_calls_gated")
                        or audit.get("tool_gate_decision_count")
                        or audit.get("agentbrake_checked_calls")
                        or 0
                    ),
                    blocked_tool_call_count=int(audit.get("blocked_tool_calls") or audit.get("agentbrake_blocks") or 0),
                    repeated_block_count=int(audit.get("repeated_block_count") or 0),
                    policy_latency_p50_ms=float(audit.get("policy_p50_ms") or audit.get("agentbrake_p50_policy_latency_ms") or 0.0),
                    policy_latency_p95_ms=float(audit.get("policy_p95_ms") or audit.get("agentbrake_p95_policy_latency_ms") or 0.0),
                )
            )
        for row in data.get("normalized_cases") or build_cases_from_legacy_summary(data):
            method = row.get("method") or data.get("defense")
            if method_filter is not None and str(method) != str(method_filter):
                continue
            cases.append(
                normalize_raw_agentdojo_result(
                    user_task_success=row.get("raw_agentdojo_user_task_success", row.get("utility", False)),
                    injection_task_success=row.get("raw_agentdojo_injection_task_success", row.get("security", False)),
                    suite=row.get("suite") or data.get("suite"),
                    method=method,
                    run_id=row.get("run_id") or data.get("run_name"),
                    user_task_id=row.get("user_task_id"),
                    injection_task_id=row.get("injection_task_id"),
                    tool_call_count=int(row.get("tool_call_count") or 0),
                    blocked_tool_call_count=int(row.get("blocked_tool_call_count") or 0),
                    repeated_block_count=int(row.get("repeated_block_count") or 0),
                    blocked_case=bool(row.get("blocked_case", False)),
                    first_block_step=row.get("first_block_step"),
                    first_confirmation_step=row.get("first_confirmation_step"),
                    post_block_tool_call_count=int(row.get("post_block_tool_call_count") or 0),
                    post_block_executed_tool_call_count=int(row.get("post_block_executed_tool_call_count") or 0),
                    post_block_blocked_tool_call_count=int(row.get("post_block_blocked_tool_call_count") or 0),
                    final_user_task_success=row.get("final_user_task_success"),
                    final_injection_task_success=row.get("final_injection_task_success"),
                    recovery_success=bool(row.get("recovery_success", False)),
                    post_block_secure_success=bool(row.get("post_block_secure_success", row.get("recovery_success", False))),
                    confirmation_required_count=int(row.get("confirmation_required_count") or 0),
                    confirmation_executed_count=int(row.get("confirmation_executed_count") or 0),
                    policy_latency_p50_ms=float(
                        row.get("policy_latency_p50_ms") or audit.get("policy_p50_ms") or audit.get("agentbrake_p50_policy_latency_ms") or 0.0
                    ),
                    policy_latency_p95_ms=float(
                        row.get("policy_latency_p95_ms") or audit.get("policy_p95_ms") or audit.get("agentbrake_p95_policy_latency_ms") or 0.0
                    ),
                    source_raw_file=str(path),
                )
            )
    return cases, run_aggregates


def looks_like_summary(data: dict[str, Any]) -> bool:
    return bool(data.get("per_run") or data.get("normalized_cases") or (data.get("utility_results") and data.get("security_results")))


def build_cases_from_legacy_summary(data: dict[str, Any]) -> list[dict[str, Any]]:
    if data.get("per_run"):
        return list(data["per_run"])
    rows = []
    utility = data.get("utility_results") or {}
    security = data.get("security_results") or {}
    for key, user_success in utility.items():
        user_id, injection_id = split_case_key(key)
        rows.append(
            {
                "user_task_id": user_id,
                "injection_task_id": injection_id,
                "raw_agentdojo_user_task_success": bool(user_success),
                "raw_agentdojo_injection_task_success": bool(security.get(key, False)),
            }
        )
    return rows


def split_case_key(key: str) -> tuple[str, str]:
    if "::" in key:
        left, right = key.split("::", 1)
        return left, right
    return key, "unknown"


def render_summary(metrics: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    suites = sorted({str(row.get("suite")) for row in rows if row.get("suite")})
    return "\n".join(
        [
            "# Corrected AgentDojo Summary",
            "",
            f"Metric schema: `{METRIC_SCHEMA_VERSION}`",
            "",
            "Raw logs were not modified. This report is regenerated from existing summary artifacts.",
            "",
            "| Metric | Value |",
            "|---|---:|",
            f"| user_utility | {float(metrics.get('user_utility', 0.0)):.3f} |",
            f"| targeted_asr | {float(metrics.get('targeted_asr', 0.0)):.3f} |",
            f"| security_rate | {float(metrics.get('security_rate', 0.0)):.3f} |",
            f"| secure_utility | {float(metrics.get('secure_utility', 0.0)):.3f} |",
            f"| recovery_success_rate | {_fmt_nullable(metrics.get('recovery_success_rate'))} |",
            f"| post_block_user_success_rate | {_fmt_nullable(metrics.get('post_block_user_success_rate'))} |",
            f"| confirmation_required_rate | {_fmt_nullable(metrics.get('confirmation_required_rate'))} |",
            f"| sample_count | {int(metrics.get('sample_count', 0))} |",
            "",
            f"Suites included: {', '.join(suites) if suites else 'none'}",
            "",
            "Replay benchmark metrics are intentionally reported separately and are not standard AgentDojo end-to-end scores.",
            "",
        ]
    )


def render_deprecated_mapping() -> str:
    return "\n".join(
        [
            "# Deprecated Report Mapping",
            "",
            "> Deprecated metric interpretation.",
            ">",
            "> This report may use the old ambiguous `security` field.",
            "> Use `experiments/agentdojo/reports/normalized/corrected_summary.md` instead.",
            "",
            "- Old `utility_under_attack` maps to `user_utility`.",
            "- Old raw AgentDojo `security` values are treated as `raw_agentdojo_injection_task_success` when regenerating v2 metrics.",
            "- v2 `targeted_asr = mean(raw_agentdojo_injection_task_success)`.",
            "- v2 `security_rate = 1.0 - targeted_asr`.",
            "- v2 `secure_utility = mean(raw_agentdojo_user_task_success and not raw_agentdojo_injection_task_success)`.",
            "",
        ]
    )


def _fmt_nullable(value: Any) -> str:
    return "null" if value is None else f"{float(value):.3f}"


def aggregate_rows(rows: list[dict[str, Any]], run_aggregates: list[RunAggregate] | None = None) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = (str(row.get("suite") or "unknown"), str(row.get("method") or "unknown"))
        groups.setdefault(key, []).append(row)
    out = []
    for (suite, method), items in sorted(groups.items()):
        targeted_asr = _mean(item.get("raw_agentdojo_injection_task_success") for item in items)
        user_utility = _mean(item.get("raw_agentdojo_user_task_success") for item in items)
        run_counts = [agg for agg in run_aggregates or [] if agg.suite == suite and agg.method == method]
        tool_call_count = sum(agg.tool_call_count for agg in run_counts)
        blocked_tool_call_count = sum(agg.blocked_tool_call_count for agg in run_counts)
        repeated_block_count = sum(agg.repeated_block_count for agg in run_counts)
        if not run_counts:
            tool_call_count = sum(int(item.get("tool_call_count") or 0) for item in items)
            blocked_tool_call_count = sum(int(item.get("blocked_tool_call_count") or 0) for item in items)
            repeated_block_count = sum(int(item.get("repeated_block_count") or 0) for item in items)
        out.append(
            {
                "suite": suite,
                "method": method,
                "sample_count": len(items),
                "user_utility": f"{user_utility:.6f}",
                "targeted_asr": f"{targeted_asr:.6f}",
                "security_rate": f"{1.0 - targeted_asr:.6f}",
                "secure_utility": f"{_mean(item.get('secure_utility_contribution') for item in items):.6f}",
                "tool_call_count": tool_call_count,
                "blocked_tool_call_count": blocked_tool_call_count,
                "repeated_block_count": repeated_block_count,
            }
        )
    return out


def leaderboard_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda row: (
            -float(row["secure_utility"]),
            float(row["targeted_asr"]),
            -float(row["user_utility"]),
        ),
    )


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _mean(values: Any) -> float:
    rows = list(values)
    return sum(1.0 if value else 0.0 for value in rows) / len(rows) if rows else 0.0


def ensure_metric_schema(out_dir: Path) -> None:
    schema = out_dir / "metric_schema.md"
    if schema.exists():
        return
    schema.write_text(
        "# AgentDojo Metrics Schema v2\n\n"
        "- `user_utility = mean(raw_agentdojo_user_task_success)`\n"
        "- `targeted_asr = mean(raw_agentdojo_injection_task_success)`\n"
        "- `security_rate = 1.0 - targeted_asr`\n"
        "- `secure_utility = mean(user_success and not injection_success)`\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
