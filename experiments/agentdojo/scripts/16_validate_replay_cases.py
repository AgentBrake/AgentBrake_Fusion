from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

DERIVED_REQUIRED = {
    "case_schema_version",
    "case_id",
    "source",
    "source_trace",
    "source_trace_file",
    "source_raw_file",
    "suite",
    "method",
    "model",
    "attack",
    "user_task_id",
    "injection_task_id",
    "label",
    "prior",
    "prior_messages",
    "prior_tool_results",
    "current_tool_call",
    "tool_call",
    "expected_decision",
    "ground_truth_violation",
    "expected_reason_codes",
    "label_source",
    "review_status",
    "case_origin",
    "standard_agentdojo_e2e_score",
    "expected_agentdojo_user_success",
    "expected_agentdojo_injection_success",
}

READ_ONLY_TOOLS = ("get_", "read_", "search_", "list_", "lookup", "open_")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate AgentDojo replay cases, manifest, and review queue")
    parser.add_argument("--cases-dir", type=Path, required=True)
    parser.add_argument("--schema", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--review-queue", type=Path, default=None)
    args = parser.parse_args()
    cases_dir = _canonical_cases_dir(args.cases_dir)
    manifest = args.manifest or cases_dir.parent / "manifest_agentdojo_derived.json"
    review_queue = args.review_queue or cases_dir.parent / "review_queue.jsonl"
    errors = validate_replay_cases(cases_dir, manifest_path=manifest, review_queue_path=review_queue)
    if errors:
        for error in errors:
            print(error)
        return 1
    print("replay cases valid")
    return 0


def _canonical_cases_dir(cases_dir: Path) -> Path:
    if (cases_dir / "safe").is_dir() and (cases_dir / "unsafe").is_dir():
        return cases_dir
    derived = cases_dir / "agentdojo_derived"
    if (derived / "safe").is_dir() and (derived / "unsafe").is_dir():
        return derived
    return cases_dir


def validate_replay_cases(cases_dir: Path, *, manifest_path: Path, review_queue_path: Path) -> list[str]:
    errors: list[str] = []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors.extend(validate_manifest(manifest, manifest_path))
    cases = load_cases(cases_dir)
    case_ids = {case.get("case_id") for _path, case in cases}
    for path in sorted((cases_dir / "local_allow_candidates").glob("*.json")):
        case_ids.add(json.loads(path.read_text(encoding="utf-8")).get("case_id"))
    if int(manifest.get("case_count", -1)) != len(cases):
        errors.append("manifest case_count does not match safe+unsafe case files")
    if int(manifest.get("safe_case_count", -1)) != sum(1 for _path, case in cases if case.get("label") == "safe"):
        errors.append("manifest safe_case_count mismatch")
    if int(manifest.get("unsafe_case_count", -1)) != sum(1 for _path, case in cases if case.get("label") == "unsafe"):
        errors.append("manifest unsafe_case_count mismatch")
    for path, case in cases:
        errors.extend(validate_case(case, path))
    review_rows = [json.loads(line) for line in review_queue_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for index, row in enumerate(review_rows, 1):
        missing = {"needs_review", "review_question", "review_status"} - set(row)
        if missing:
            errors.append(f"{review_queue_path}:{index}: missing {sorted(missing)}")
        if not row.get("case_id"):
            errors.append(f"{review_queue_path}:{index}: case_id required")
        if row.get("case_id") in case_ids and not row.get("label"):
            errors.append(f"{review_queue_path}:{index}: counted case review row requires label")
    return errors


def validate_manifest(manifest: dict[str, Any], path: Path) -> list[str]:
    errors = []
    for field in ("benchmark_type", "standard_agentdojo_e2e_score", "counts_by_suite", "counts_by_violation_type", "review_status_counts"):
        if field not in manifest:
            errors.append(f"{path}: missing manifest field {field}")
    if manifest.get("benchmark_type") != "agentdojo_derived_tool_boundary_replay":
        errors.append(f"{path}: invalid benchmark_type")
    if manifest.get("standard_agentdojo_e2e_score") is not False:
        errors.append(f"{path}: standard_agentdojo_e2e_score must be false")
    if set((manifest.get("counts_by_violation_type") or {}).keys()) == {"unknown"}:
        errors.append(f"{path}: counts_by_violation_type must not be all unknown")
    for case in manifest.get("cases") or []:
        if "\\" in str(case.get("path", "")):
            errors.append(f"{path}: manifest paths must use POSIX '/' separators")
    return errors


def validate_case(case: dict[str, Any], path: Path) -> list[str]:
    missing = sorted(DERIVED_REQUIRED - set(case))
    errors = [f"{path}: missing {missing}"] if missing else []
    if case.get("case_schema_version") != "agentdojo_replay_case_v1":
        errors.append(f"{path}: invalid case_schema_version")
    if case.get("standard_agentdojo_e2e_score") is not False:
        errors.append(f"{path}: standard_agentdojo_e2e_score must be false")
    if case.get("label") not in {"unsafe", "safe"}:
        errors.append(f"{path}: main benchmark label must be safe or unsafe")
    if case.get("label") == "safe" and not (case.get("expected_agentdojo_user_success") is True and case.get("expected_agentdojo_injection_success") is False):
        errors.append(f"{path}: safe case must have user_success=true and injection_success=false")
    if case.get("label") == "unsafe":
        tool = str((case.get("current_tool_call") or {}).get("tool") or "")
        if tool == "get_webpage" or tool.startswith(READ_ONLY_TOOLS):
            errors.append(f"{path}: unsafe case must not use read-only tool {tool}")
    for field in ("source_trace", "source_trace_file", "source_raw_file"):
        if "\\" in str(case.get(field, "")):
            errors.append(f"{path}: {field} must use POSIX '/' separators")
    call = case.get("current_tool_call") or {}
    if not isinstance(call, dict) or "tool" not in call or "args" not in call:
        errors.append(f"{path}: current_tool_call requires tool and args")
    violation = case.get("ground_truth_violation") or {}
    if not isinstance(violation, dict) or not violation.get("type"):
        errors.append(f"{path}: ground_truth_violation.type required")
    return errors


def load_cases(cases_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    cases: list[tuple[Path, dict[str, Any]]] = []
    for label in ("unsafe", "safe"):
        for path in sorted((cases_dir / label).glob("*.json")):
            cases.append((path, json.loads(path.read_text(encoding="utf-8"))))
    return cases


if __name__ == "__main__":
    raise SystemExit(main())
