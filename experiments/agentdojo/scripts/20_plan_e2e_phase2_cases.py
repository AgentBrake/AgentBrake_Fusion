from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REPLAY = ROOT / "experiments" / "agentdojo" / "replay_cases"
DEFAULT_REPORTS = ROOT / "experiments" / "agentdojo" / "reports" / "deepseekv4_flash"
DEFAULT_OUT = DEFAULT_REPORTS / "e2e_phase2"
SUITES = ("banking", "slack", "travel", "workspace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan AgentDojo Phase 2 E2E task pairs from Phase 1.2 replay cases")
    parser.add_argument("--replay-cases-dir", type=Path, default=DEFAULT_REPLAY)
    parser.add_argument("--phase1-reports-dir", type=Path, default=DEFAULT_REPORTS)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--mode", choices=["minimal", "medium", "formal"], default="minimal")
    parser.add_argument("--cases-per-suite", type=int, default=12)
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--include-case", action="append", default=[], help="Extra suite:user_task_id:injection_task_id pair to include")
    args = parser.parse_args()

    plan = build_case_plan(
        replay_cases_dir=args.replay_cases_dir,
        phase1_reports_dir=args.phase1_reports_dir,
        mode=args.mode,
        cases_per_suite=args.cases_per_suite,
        attack=args.attack,
        include_cases=args.include_case,
    )
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "case_plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    (args.out_dir / "case_plan.md").write_text(render_markdown(plan), encoding="utf-8")
    print(args.out_dir / "case_plan.json")
    return 0


def build_case_plan(
    *,
    replay_cases_dir: Path,
    phase1_reports_dir: Path,
    mode: str,
    cases_per_suite: int,
    attack: str,
    include_cases: list[str] | None = None,
) -> dict[str, Any]:
    cases = load_replay_cases(replay_cases_dir / "agentdojo_derived")
    grouped: dict[str, dict[tuple[str, str], list[dict[str, Any]]]] = {suite: defaultdict(list) for suite in SUITES}
    for case in cases:
        suite = str(case.get("suite") or "")
        if suite not in grouped:
            continue
        user_task_id = normalize_task_id(case.get("user_task_id"), "user_task_")
        injection_task_id = normalize_task_id(case.get("injection_task_id"), "injection_task_")
        if not user_task_id or not injection_task_id:
            continue
        grouped[suite][(user_task_id, injection_task_id)].append(case)

    rows: list[dict[str, Any]] = []
    selected_keys: set[tuple[str, str, str]] = set()
    for suite in SUITES:
        candidates = sorted(grouped[suite].items(), key=lambda item: pair_sort_key(item), reverse=True)
        selected = select_balanced_pairs(candidates, cases_per_suite)
        if len(selected) < cases_per_suite:
            selected.extend(supplement_direct_agentdojo_pairs(suite, selected, cases_per_suite - len(selected)))
        for (user_task_id, injection_task_id), related in selected:
            rows.append(plan_row(suite, user_task_id, injection_task_id, related, attack))
            selected_keys.add((suite, user_task_id, injection_task_id))

    for suite, user_task_id, injection_task_id in parse_include_cases(include_cases or []):
        if (suite, user_task_id, injection_task_id) in selected_keys:
            continue
        related = list(grouped.get(suite, {}).get((user_task_id, injection_task_id), []))
        rows.append(plan_row(suite, user_task_id, injection_task_id, related, attack, forced=True))
        selected_keys.add((suite, user_task_id, injection_task_id))

    return {
        "schema_version": "agentbrake_agentdojo_phase2_case_plan_v1",
        "experiment_type": "agentdojo_e2e_defended_run",
        "phase": "phase2",
        "mode": mode,
        "model": "deepseek-v4-flash",
        "attack": attack,
        "case_count": len(rows),
        "cases_per_suite_target": cases_per_suite,
        "phase1_replay_summary": str((phase1_reports_dir / "replay" / "agentdojo_derived_replay_summary.json").as_posix()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cases": rows,
    }


def plan_row(
    suite: str,
    user_task_id: str,
    injection_task_id: str,
    related: list[dict[str, Any]],
    attack: str,
    *,
    forced: bool = False,
) -> dict[str, Any]:
    risk_types = sorted({str((case.get("ground_truth_violation") or {}).get("type")) for case in related if case.get("ground_truth_violation")})
    tools = sorted({str((case.get("current_tool_call") or {}).get("tool")) for case in related if case.get("current_tool_call")})
    labels = {str(case.get("label")) for case in related}
    reason = selection_reason(labels, risk_types) if related else "agentdojo_direct_suite_supplement"
    if forced:
        reason = f"forced_{reason}"
    return {
        "phase2_case_id": f"phase2_{suite}_{user_task_id}_{injection_task_id}",
        "suite": suite,
        "user_task_id": user_task_id,
        "injection_task_id": injection_task_id,
        "attack": attack,
        "source": "agentdojo_task_pair" if related else "agentdojo_task_pair_direct",
        "selection_reason": reason,
        "phase1_related_case_ids": sorted(str(case.get("case_id")) for case in related),
        "expected_risk_types": risk_types,
        "expected_sensitive_tools": tools,
        "priority": "high" if "unsafe" in labels else ("medium" if related else "low"),
    }


def parse_include_cases(values: list[str]) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for value in values:
        parts = [part.strip() for part in value.split(":")]
        if len(parts) != 3:
            raise ValueError("--include-case must use suite:user_task_id:injection_task_id")
        suite, user_task_id, injection_task_id = parts
        rows.append((suite, normalize_task_id(user_task_id, "user_task_"), normalize_task_id(injection_task_id, "injection_task_")))
    return rows


def load_replay_cases(derived_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for label in ("unsafe", "safe"):
        for path in sorted((derived_dir / label).glob("*.json")):
            rows.append(json.loads(path.read_text(encoding="utf-8")))
    return rows


def select_balanced_pairs(
    candidates: list[tuple[tuple[str, str], list[dict[str, Any]]]],
    limit: int,
) -> list[tuple[tuple[str, str], list[dict[str, Any]]]]:
    if limit <= 0:
        return []

    unsafe = [item for item in candidates if labels_for(item[1]) == {"unsafe"}]
    mixed = [item for item in candidates if labels_for(item[1]) == {"safe", "unsafe"}]
    safe = [item for item in candidates if labels_for(item[1]) == {"safe"}]

    minimum_risk_quota = 10 if limit >= 25 else 2
    risk_quota = min(len(unsafe) + len(mixed), max(minimum_risk_quota, limit // 3))
    utility_quota = max(0, limit - risk_quota)
    selected: list[tuple[tuple[str, str], list[dict[str, Any]]]] = []

    def add_from(pool: list[tuple[tuple[str, str], list[dict[str, Any]]]], count: int) -> None:
        seen = {item[0] for item in selected}
        for item in pool:
            if len([row for row in selected if labels_for(row[1]) & labels_for(item[1])]) >= count:
                break
            if item[0] not in seen:
                selected.append(item)
                seen.add(item[0])

    add_from(diversify_by_user_task(mixed + unsafe), risk_quota)
    add_from(diversify_by_user_task(safe), utility_quota)
    for item in candidates:
        if len(selected) >= limit:
            break
        if item[0] not in {row[0] for row in selected}:
            selected.append(item)

    return selected[:limit]


def supplement_direct_agentdojo_pairs(
    suite_name: str,
    selected: list[tuple[tuple[str, str], list[dict[str, Any]]]],
    count: int,
) -> list[tuple[tuple[str, str], list[dict[str, Any]]]]:
    if count <= 0:
        return []
    try:
        suite = import_module("agentdojo.task_suite.load_suites").get_suite("v1.2.2", suite_name)
    except Exception:
        return []
    selected_keys = {key for key, _related in selected}
    user_ids = sorted([str(getattr(task, "ID", task)) for task in user_task_values(suite)], key=task_number)
    injection_ids = sorted([str(item) for item in getattr(suite, "injection_tasks", {})], key=task_number)
    out: list[tuple[tuple[str, str], list[dict[str, Any]]]] = []
    for user_task_id in user_ids:
        for injection_task_id in injection_ids:
            key = (user_task_id, injection_task_id)
            if key in selected_keys:
                continue
            out.append((key, []))
            selected_keys.add(key)
            if len(out) >= count:
                return out
    return out


def user_task_values(suite: Any) -> list[Any]:
    user_tasks = getattr(suite, "user_tasks", [])
    return list(user_tasks.values()) if hasattr(user_tasks, "values") else list(user_tasks)


def diversify_by_user_task(
    candidates: list[tuple[tuple[str, str], list[dict[str, Any]]]],
) -> list[tuple[tuple[str, str], list[dict[str, Any]]]]:
    buckets: dict[str, list[tuple[tuple[str, str], list[dict[str, Any]]]]] = defaultdict(list)
    for item in candidates:
        buckets[item[0][0]].append(item)
    ordered: list[tuple[tuple[str, str], list[dict[str, Any]]]] = []
    while buckets:
        for user_task_id in sorted(list(buckets), key=task_number):
            bucket = buckets[user_task_id]
            ordered.append(bucket.pop(0))
            if not bucket:
                del buckets[user_task_id]
    return ordered


def labels_for(cases: list[dict[str, Any]]) -> set[str]:
    return {str(case.get("label")) for case in cases if case.get("label")}


def pair_sort_key(item: tuple[tuple[str, str], list[dict[str, Any]]]) -> tuple[int, int, int, int]:
    (user_task_id, injection_task_id), cases = item
    return (*pair_score(cases), -task_number(user_task_id), -task_number(injection_task_id))


def pair_score(cases: list[dict[str, Any]]) -> tuple[int, int, int]:
    labels = {case.get("label") for case in cases}
    has_unsafe = int("unsafe" in labels)
    has_safe = int("safe" in labels)
    return has_unsafe + has_safe, has_unsafe, len(cases)


def task_number(task_id: str) -> int:
    try:
        return int(task_id.rsplit("_", 1)[1])
    except (IndexError, ValueError):
        return 0


def selection_reason(labels: set[str], risk_types: list[str]) -> str:
    if "unsafe" in labels and "safe" in labels:
        return "phase1_unsafe_and_utility_sensitive"
    if "unsafe" in labels:
        return "phase1_unsafe_or_recovery_sensitive"
    if any("benign" in item for item in risk_types):
        return "phase1_utility_sensitive"
    return "phase1_related_task_pair"


def normalize_task_id(value: Any, prefix: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    return text if text.startswith(prefix) else f"{prefix}{text}"


def render_markdown(plan: dict[str, Any]) -> str:
    lines = [
        "# AgentDojo Phase 2 E2E Case Plan",
        "",
        f"- mode: `{plan['mode']}`",
        f"- model: `{plan['model']}`",
        f"- attack: `{plan['attack']}`",
        f"- case_count: {plan['case_count']}",
        "",
        "| case | suite | user_task | injection_task | reason | risks |",
        "|---|---|---|---|---|---|",
    ]
    for row in plan["cases"]:
        risks = ", ".join(row["expected_risk_types"])
        lines.append(
            f"| {row['phase2_case_id']} | {row['suite']} | {row['user_task_id']} | {row['injection_task_id']} | {row['selection_reason']} | {risks} |"
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
