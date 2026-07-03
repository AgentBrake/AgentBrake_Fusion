from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agentbrake.eval.agentdojo.runner.metrics import compute_recovery_metrics

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_IN = ROOT / "experiments" / "agentdojo" / "reports" / "paired_mini"


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize paired AgentDojo mini benchmark")
    parser.add_argument("--input-dir", "--input", dest="input_dir", type=Path, default=DEFAULT_IN)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    rows = [
        row
        for row in (json.loads(path.read_text(encoding="utf-8")) for path in sorted(args.input_dir.glob("*.json")))
        if isinstance(row, dict)
    ]
    summary = {"metric_schema_version": "agentdojo_metrics_v2", "runs": []}
    for row in rows:
        audit = row.get("agentdojo_firewall_audit_summary") or row.get("agentbrake_audit_summary") or {}
        case_ids = sorted(case.get("case_id") for case in row.get("normalized_cases", []) if case.get("case_id"))
        if not case_ids and row.get("per_run"):
            case_ids = sorted(f"{item.get('suite', row.get('suite'))}_user_task_{item.get('user_task_id')}_injection_task_{item.get('injection_task_id')}" for item in row["per_run"])
        recovery = compute_recovery_metrics(row.get("normalized_cases", []))
        summary["runs"].append(
            {
                "run_name": row.get("run_name"),
                "suite": row.get("suite"),
                "method": row.get("defense"),
                "model": row.get("model"),
                "attack": row.get("attack"),
                "user_utility": row.get("user_utility", row.get("utility_under_attack", 0.0)),
                "targeted_asr": row.get("targeted_asr", 0.0),
                "security_rate": row.get("security_rate", row.get("security", 0.0)),
                "secure_utility": row.get("secure_utility", 0.0),
                "block_rate": _block_rate(audit),
                "false_positive_rate": row.get("false_positive_rate", 0.0),
                "policy_latency_p50": audit.get("policy_p50_ms") or audit.get("agentbrake_p50_policy_latency_ms", 0.0),
                "policy_latency_p95": audit.get("policy_p95_ms") or audit.get("agentbrake_p95_policy_latency_ms", 0.0),
                "tool_call_count": audit.get("tool_gate_decision_count") or audit.get("agentbrake_checked_calls", 0),
                "blocked_tool_call_count": audit.get("blocked_tool_calls") or audit.get("agentbrake_blocks", 0),
                "repeated_block_count": audit.get("repeated_block_count", 0),
                "case_ids": case_ids,
                **recovery,
            }
        )
    baseline_by_suite = {
        row["suite"]: row["user_utility"]
        for row in summary["runs"]
        if row.get("method") in {"none", "no_defense"} or str(row.get("run_name", "")).find("no_defense") >= 0
    }
    for row in summary["runs"]:
        baseline = baseline_by_suite.get(row["suite"], row["user_utility"])
        row["utility_drop"] = float(baseline or 0.0) - float(row.get("user_utility") or 0.0)
    summary["paired_integrity"] = paired_integrity(summary["runs"])
    out = args.out or (args.input_dir / "paired_summary.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(out)
    return 0


def _block_rate(audit: dict[str, Any]) -> float:
    total = int(audit.get("tool_gate_decision_count") or audit.get("agentbrake_checked_calls") or 0)
    blocked = int(audit.get("blocked_tool_calls") or audit.get("agentbrake_blocks") or 0)
    return blocked / total if total else 0.0


def paired_integrity(runs: list[dict[str, Any]]) -> dict[str, Any]:
    by_suite: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        by_suite.setdefault(str(run.get("suite")), []).append(run)
    mismatches = []
    for suite, suite_runs in sorted(by_suite.items()):
        non_empty = [run for run in suite_runs if run.get("case_ids")]
        if not non_empty:
            continue
        reference = set(non_empty[0]["case_ids"])
        for run in non_empty[1:]:
            current = set(run["case_ids"])
            if current != reference:
                mismatches.append(
                    {
                        "suite": suite,
                        "method": run.get("method"),
                        "missing": sorted(reference - current),
                        "extra": sorted(current - reference),
                    }
                )
    return {"paired": not mismatches, "mismatches": mismatches}


if __name__ == "__main__":
    raise SystemExit(main())
