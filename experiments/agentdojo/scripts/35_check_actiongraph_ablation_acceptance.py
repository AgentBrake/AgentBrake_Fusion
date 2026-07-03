from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ACTIONGRAPH_NEW_VARIANTS = (
    "flatten_action_graph",
    "no_actiongraph_provenance_edges",
    "no_actiongraph_dataflow_edges",
    "no_actiongraph_history_edges",
)
ACTIONGRAPH_VARIANTS = ("full", *ACTIONGRAPH_NEW_VARIANTS)
REQUIRED_FILES = (
    "actiongraph_ablation_case_plan.json",
    "actiongraph_ablation_case_plan.sha256",
    "actiongraph_bucket_labels.json",
    "actiongraph_bucket_labels.csv",
    "run_plan_all_variants.json",
    "run_manifest_all_variants.json",
    "actiongraph_per_case_results.jsonl",
    "actiongraph_diagnostic_summary.json",
    "actiongraph_diagnostic_summary.md",
    "actiongraph_diagnostic_main_table.csv",
    "actiongraph_pairwise_delta.json",
    "actiongraph_pairwise_delta.md",
    "actiongraph_pairwise_delta_by_suite.csv",
    "actiongraph_bucket_breakdown.csv",
    "actiongraph_reason_code_fidelity.json",
    "actiongraph_reason_code_fidelity.md",
    "artifact_manifest.json",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check AgentBrake-Fusion ActionGraph ablation acceptance")
    parser.add_argument("--reports-dir", type=Path, required=True)
    parser.add_argument("--source-ablation-dir", type=Path, required=True)
    args = parser.parse_args()
    result = check(args.reports_dir, args.source_ablation_dir)
    write_json(args.reports_dir / "actiongraph_acceptance.json", result)
    (args.reports_dir / "actiongraph_acceptance.md").write_text(render_md(result), encoding="utf-8")
    print(args.reports_dir / "actiongraph_acceptance.json")
    return 0 if result["overall_status"] in {"PASS", "WARN"} else 1


def check(root: Path, source_ablation_dir: Path) -> dict[str, Any]:
    checks: dict[str, bool] = {f"{name}_exists": (root / name).exists() for name in REQUIRED_FILES}
    plan = read_json(root / "actiongraph_ablation_case_plan.json") if checks["actiongraph_ablation_case_plan.json_exists"] else {}
    summary = read_json(root / "actiongraph_diagnostic_summary.json") if checks["actiongraph_diagnostic_summary.json_exists"] else {}
    manifest = read_json(root / "run_manifest_all_variants.json") if checks["run_manifest_all_variants.json_exists"] else {}
    artifact_manifest = read_json(root / "artifact_manifest.json") if checks["artifact_manifest.json_exists"] else {}
    rows = read_jsonl(root / "actiongraph_per_case_results.jsonl") if checks["actiongraph_per_case_results.jsonl_exists"] else []

    source_plan_path = source_ablation_dir / "ablation_diagnostic_case_plan.json"
    source_plan = read_json(source_plan_path) if source_plan_path.exists() else {}
    checks.update(
        {
            "no_active_no_context_graph_variant": "no_context_graph" not in set(plan.get("variants") or manifest.get("variants") or []),
            "legacy_no_context_graph_not_in_main_table": legacy_absent_from_main(root),
            "case_set_consistency_pass": same_case_set(plan, source_plan),
            "case_plan_sha256_matches": sha_matches(root / "actiongraph_ablation_case_plan.json", root / "actiongraph_ablation_case_plan.sha256"),
            "actiongraph_bucket_labels_exists": (root / "actiongraph_bucket_labels.json").exists() and (root / "actiongraph_bucket_labels.csv").exists(),
            "run_plan_all_variants_exists": (root / "run_plan_all_variants.json").exists(),
            "run_manifest_all_variants_exists": (root / "run_manifest_all_variants.json").exists(),
            "new_variant_run_count_matches": new_variant_run_count_matches(manifest, plan),
            "full_baseline_reuse_declared": bool(artifact_manifest.get("baseline_reuse", {}).get("declared")),
            "actiongraph_per_case_results_rows_match": len(rows) == int(plan.get("case_count") or 0) * len(ACTIONGRAPH_VARIANTS),
            "all_trace_files_exist": all_trace_files_exist(rows),
            "trace_schema_version_valid": trace_schema_valid(rows),
            "summary_exists": bool(summary),
            "pairwise_delta_exists": (root / "actiongraph_pairwise_delta.json").exists(),
            "bucket_breakdown_exists": (root / "actiongraph_bucket_breakdown.csv").exists(),
            "reason_code_fidelity_exists": (root / "actiongraph_reason_code_fidelity.json").exists(),
        }
    )
    scan = artifact_scan(root)
    checks["no_secret"] = not scan["secret_hits"]
    checks["no_local_path"] = not scan["local_path_hits"]
    structural_acceptance = "PASS" if all(checks.values()) else "FAIL"
    interpretation_acceptance = "PASS"
    if summary.get("contribution_flags", {}).get("overall", {}).get("status") == "not_clearly_separated":
        interpretation_acceptance = "WARN"
    overall_status = structural_acceptance if structural_acceptance == "FAIL" else interpretation_acceptance
    return {
        "experiment": "qwen_plus_actiongraph_ablation_diagnostic",
        "structural_acceptance": structural_acceptance,
        "interpretation_acceptance": interpretation_acceptance,
        "overall_status": overall_status,
        "checks": checks,
        "scan": scan,
    }


def same_case_set(plan: dict[str, Any], source_plan: dict[str, Any]) -> bool:
    current = {(str(c.get("suite")), str(c.get("user_task_id")), str(c.get("injection_task_id"))) for c in plan.get("cases") or []}
    source = {(str(c.get("suite")), str(c.get("user_task_id")), str(c.get("injection_task_id"))) for c in source_plan.get("cases") or []}
    return bool(current) and current == source


def new_variant_run_count_matches(manifest: dict[str, Any], plan: dict[str, Any]) -> bool:
    return int(manifest.get("completed_run_count") or -1) == int(plan.get("case_count") or 0) * len(ACTIONGRAPH_NEW_VARIANTS)


def all_trace_files_exist(rows: list[dict[str, Any]]) -> bool:
    return bool(rows) and all(row.get("trace_file") and Path(str(row["trace_file"])).exists() for row in rows)


def trace_schema_valid(rows: list[dict[str, Any]]) -> bool:
    for row in rows:
        trace_file = row.get("trace_file")
        if not trace_file or not Path(str(trace_file)).exists():
            return False
        data = read_json(Path(str(trace_file)))
        schema = str(data.get("trace_schema_version") or data.get("schema_version") or "")
        if schema and schema not in {"1", "1.0", "braketrace.v1", "agentdojo_trace_v1"}:
            return False
        if not (isinstance(data.get("audit_events"), list) or isinstance(data.get("audit"), list)):
            return False
    return bool(rows)


def legacy_absent_from_main(root: Path) -> bool:
    csv_path = root / "actiongraph_diagnostic_main_table.csv"
    md_path = root / "actiongraph_diagnostic_summary.md"
    text = ""
    if csv_path.exists():
        text += csv_path.read_text(encoding="utf-8-sig")
    if md_path.exists():
        text += md_path.read_text(encoding="utf-8-sig")
    return "no_context_graph" not in text and "legacy_no_context_graph" not in text


def sha_matches(plan_path: Path, sha_path: Path) -> bool:
    if not plan_path.exists() or not sha_path.exists():
        return False
    data = read_json(plan_path)
    digest = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    return sha_path.read_text(encoding="utf-8-sig").strip() == digest


def artifact_scan(root: Path) -> dict[str, Any]:
    secret_hits = []
    local_path_hits = []
    secret_re = re.compile(r"sk-(?!external)[A-Za-z0-9]{8,}")
    local_path_re = re.compile(r"((?<![A-Za-z])[A-Za-z]:(?:\\\\|/)|/home/|file://)")
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl", ".md", ".csv", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
        if secret_re.search(text):
            secret_hits.append(path.relative_to(root).as_posix())
        if local_path_re.search(text):
            local_path_hits.append(path.relative_to(root).as_posix())
    return {"secret_hits": sorted(secret_hits), "local_path_hits": sorted(local_path_hits)}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def render_md(result: dict[str, Any]) -> str:
    lines = [
        "# ActionGraph Ablation Acceptance",
        "",
        f"- structural_acceptance: {result['structural_acceptance']}",
        f"- interpretation_acceptance: {result['interpretation_acceptance']}",
        f"- overall_status: {result['overall_status']}",
        "",
        "| Check | Pass |",
        "|---|---:|",
    ]
    for key, value in result["checks"].items():
        lines.append(f"| {key} | {value} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
