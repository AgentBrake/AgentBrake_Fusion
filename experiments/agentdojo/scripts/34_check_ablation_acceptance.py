from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

VARIANTS = ("rule_only", "no_binding", "no_context_graph", "no_recovery_guidance")
PUBLIC_SUFFIXES = {".json", ".jsonl", ".md", ".txt", ".csv", ".yaml", ".yml"}
SECRET_PATTERNS = ("sk-", "api_key", "authorization:", "password", "token", "secret")
LOCAL_PATH_PATTERNS = ("E:\\", "C:\\", "/home/", "file://")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check Qwen-Plus ablation diagnostic acceptance")
    parser.add_argument("--ablation-dir", type=Path, required=True)
    args = parser.parse_args()
    out = check(args.ablation_dir)
    write_json(args.ablation_dir / "ablation_acceptance.json", out)
    (args.ablation_dir / "ablation_acceptance.md").write_text(render_md(out), encoding="utf-8")
    print(args.ablation_dir / "ablation_acceptance.json")
    return 0 if out["final_status"] == "PASS" else 1


def check(root: Path) -> dict[str, Any]:
    plan_path = root / "ablation_diagnostic_case_plan.json"
    summary_path = root / "ablation_diagnostic_summary.json"
    main_csv = root / "ablation_diagnostic_main_table.csv"
    plan = json.loads(plan_path.read_text(encoding="utf-8-sig")) if plan_path.exists() else {}
    summary = json.loads(summary_path.read_text(encoding="utf-8-sig")) if summary_path.exists() else {}
    checks = {
        "case_plan_exists": plan_path.exists(),
        "case_count_500": int(plan.get("case_count") or 0) == 500,
        "all_4_variants_completed": all(count_variant_raw(root, variant) == 500 for variant in VARIANTS),
        "per_case_rows_new_variants_2000": sum(count_variant_raw(root, variant) for variant in VARIANTS) == 2000,
        "full_baseline_reused_rows_500": (summary.get("case_count_by_variant") or {}).get("full") == 500,
        "full_trace_missing_zero": count_missing_traces(root) == 0,
        "ablation_profile_recorded": traces_have_field(root, "ablation_profile"),
        "modules_recorded": traces_have_field(root, "modules_enabled") and traces_have_field(root, "modules_disabled"),
        "artifact_hygiene": artifact_hygiene(root),
        "main_table_exactly_5_rows": count_csv_rows(main_csv) == 5,
        "summary_json_valid": bool(summary),
        "csv_valid": main_csv.exists(),
    }
    final = "PASS" if all(checks.values()) else "FAIL"
    return {
        "experiment": "qwen_plus_ablation_diagnostic",
        "final_status": final,
        "checks": checks,
        "case_count": plan.get("case_count"),
        "new_variant_rows": sum(count_variant_raw(root, variant) for variant in VARIANTS),
        "missing_trace_count": count_missing_traces(root),
        "main_table_rows": count_csv_rows(main_csv),
    }


def count_variant_raw(root: Path, variant: str) -> int:
    return len(list((root / "raw_runs").glob(f"*_{variant}.json")))


def count_missing_traces(root: Path) -> int:
    missing = 0
    for variant in VARIANTS:
        for raw in (root / "raw_runs").glob(f"*_{variant}.json"):
            data = json.loads(raw.read_text(encoding="utf-8-sig"))
            for row in data.get("per_run") or []:
                trace = row.get("trace_file")
                if not trace or not Path(str(trace)).exists():
                    missing += 1
    return missing


def traces_have_field(root: Path, field: str) -> bool:
    for variant in VARIANTS:
        traces = list((root / "full_traces" / variant).rglob("*.json"))
        if not traces:
            return False
        variant_has_decision = False
        for path in traces[:20]:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            events = data.get("audit_events") or []
            decisions = [event for event in events if event.get("event_type") == "agentdojo_tool_gate_decision"]
            if decisions:
                variant_has_decision = True
                if not all(field in event for event in decisions):
                    return False
        if not variant_has_decision:
            return False
    return True


def artifact_hygiene(root: Path) -> bool:
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in PUBLIC_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
        lowered = text.lower()
        if any(pattern.lower() in lowered for pattern in SECRET_PATTERNS):
            return False
        if any(pattern in text for pattern in LOCAL_PATH_PATTERNS):
            return False
    return True


def count_csv_rows(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(newline="", encoding="utf-8-sig") as f:
        return sum(1 for _ in csv.DictReader(f))


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def render_md(data: dict[str, Any]) -> str:
    lines = ["# Qwen-Plus Ablation Acceptance", "", f"- final_status: {data['final_status']}", ""]
    for key, value in data["checks"].items():
        lines.append(f"- {key}: {'PASS' if value else 'FAIL'}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
