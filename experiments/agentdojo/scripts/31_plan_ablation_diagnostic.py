from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

SIDE_EFFECT_TOOLS = {
    "send_money",
    "schedule_transaction",
    "update_scheduled_transaction",
    "reserve_hotel",
    "reserve_restaurant",
    "book_flight",
    "send_direct_message",
    "send_channel_message",
    "invite_user_to_slack",
    "add_user_to_channel",
    "send_email",
    "create_calendar_event",
    "update_calendar_event",
    "delete_file",
    "delete_email",
    "share_file",
    "create_file",
    "modify_file",
    "append_to_file",
    "reschedule_calendar_event",
    "add_calendar_event_participants",
    "update_password",
    "update_user_info",
    "remove_user_from_slack",
    "post_webpage",
}

FULL_E2E_FALLBACK = Path("experiments/agentdojo/reports/cross_model/qwen_plus/e2e_full_agentdojo")


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan Qwen-Plus 500-case ablation diagnostic set")
    parser.add_argument("--full-e2e-dir", type=Path, default=None)
    parser.add_argument("--source-case-plan", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--mode", default="standard", choices=["standard", "actiongraph_targeted_same_cases"])
    parser.add_argument("--target-size", type=int, default=500)
    parser.add_argument("--blocked-critical-cap", type=int, default=120)
    parser.add_argument("--model", default="qwen-plus")
    parser.add_argument("--attack", default="important_instructions")
    args = parser.parse_args()

    if args.mode == "actiongraph_targeted_same_cases":
        if args.source_case_plan is None:
            raise ValueError("--source-case-plan is required for actiongraph_targeted_same_cases")
        return plan_actiongraph_same_cases(args)
    if args.full_e2e_dir is None:
        raise ValueError("--full-e2e-dir is required for standard planning")
    full_dir = resolve_full_e2e_dir(args.full_e2e_dir)
    rows = load_rows(full_dir / "per_case_results.jsonl")
    by_case = group_by_case(rows)
    selected: dict[tuple[str, str, str], dict[str, Any]] = {}
    sources: dict[str, list[str]] = defaultdict(list)

    attack_active = [
        case for case in by_case.values() if bool(case.get("no_defense", {}).get("raw_agentdojo_injection_task_success"))
    ]
    add_cases(selected, sources, attack_active, "attack_active", full_dir, args.model, args.attack)

    blocked_candidates = [
        case
        for case in by_case.values()
        if bool(case.get("agentbrake_strict", {}).get("blocked_case"))
        or int(case.get("agentbrake_strict", {}).get("require_confirmation_count") or 0) > 0
    ]
    blocked_candidates = sorted(blocked_candidates, key=blocked_sort_key)[: args.blocked_critical_cap]
    add_cases(selected, sources, blocked_candidates, "blocked_critical", full_dir, args.model, args.attack)

    safe_candidates = [
        case
        for case in by_case.values()
        if bool(case.get("no_defense", {}).get("raw_agentdojo_user_task_success"))
        and not bool(case.get("no_defense", {}).get("raw_agentdojo_injection_task_success"))
        and primary_side_effect_tool(case, full_dir)
    ]
    for case in sorted(safe_candidates, key=case_sort_key):
        if len(selected) >= args.target_size:
            break
        add_cases(selected, sources, [case], "safe_side_effect_control", full_dir, args.model, args.attack)

    cases = sorted(selected.values(), key=plan_case_sort_key)[: args.target_size]
    plan = {
        "experiment": "qwen_plus_ablation_diagnostic",
        "model": args.model,
        "attack": args.attack,
        "case_selection_source_model": "deepseek-v4-flash",
        "evaluation_model": args.model,
        "source_full_e2e_dir": str(full_dir.as_posix()),
        "target_size": args.target_size,
        "blocked_critical_cap": args.blocked_critical_cap,
        "case_count": len(cases),
        "cases": cases,
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    plan_path = args.out_dir / "ablation_diagnostic_case_plan.json"
    write_json(plan_path, plan)
    digest = hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()
    (args.out_dir / "ablation_diagnostic_case_plan.sha256").write_text(digest, encoding="utf-8")
    write_json(args.out_dir / "ablation_diagnostic_case_sources.json", sources)
    (args.out_dir / "ablation_diagnostic_case_plan.md").write_text(render_plan_md(plan, sources), encoding="utf-8")
    (args.out_dir / "ablation_diagnostic_gap_report.md").write_text(render_gap_md(plan, args.target_size), encoding="utf-8")
    print(plan_path)
    return 0 if len(cases) == args.target_size else 1


def plan_actiongraph_same_cases(args: argparse.Namespace) -> int:
    source = json.loads(args.source_case_plan.read_text(encoding="utf-8-sig"))
    cases = []
    labels = []
    for case in source["cases"]:
        bucket = actiongraph_bucket(case)
        planned = {
            **case,
            "phase2_case_id": str(case["phase2_case_id"]).replace("ablation_", "actiongraph_", 1),
            "case_id": str(case["case_id"]).replace("ablation_", "actiongraph_", 1),
            "model": args.model,
            "case_selection_source_model": "deepseek-v4-flash",
            "evaluation_model": args.model,
            "attack": args.attack,
            "actiongraph_bucket": bucket,
            "source_ablation_case_id": case["phase2_case_id"],
        }
        cases.append(planned)
        labels.append(
            {
                "phase2_case_id": planned["phase2_case_id"],
                "source_ablation_case_id": case["phase2_case_id"],
                "suite": case["suite"],
                "user_task_id": case["user_task_id"],
                "injection_task_id": case["injection_task_id"],
                "selection_reason": case.get("selection_reason"),
                "actiongraph_bucket": bucket,
                "primary_side_effect_tool": case.get("primary_side_effect_tool"),
            }
        )
    plan = {
        "experiment": "qwen_plus_actiongraph_ablation_diagnostic",
        "mode": "actiongraph_targeted_same_cases",
        "model": args.model,
        "attack": args.attack,
        "case_selection_source_model": "deepseek-v4-flash",
        "evaluation_model": args.model,
        "source_case_plan": str(args.source_case_plan.as_posix()),
        "source_case_plan_sha256": hashlib.sha256(canonical_json(source).encode("utf-8")).hexdigest(),
        "case_count": len(cases),
        "cases": cases,
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.out_dir / "actiongraph_ablation_case_plan.json", plan)
    (args.out_dir / "actiongraph_ablation_case_plan.sha256").write_text(
        hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest(),
        encoding="utf-8",
    )
    write_json(args.out_dir / "actiongraph_bucket_labels.json", labels)
    write_bucket_csv(args.out_dir / "actiongraph_bucket_labels.csv", labels)
    return 0 if len(cases) == int(source.get("case_count") or len(source["cases"])) else 1


def actiongraph_bucket(case: dict[str, Any]) -> str:
    reason = str(case.get("selection_reason") or "")
    tool = str(case.get("primary_side_effect_tool") or "")
    if reason == "attack_active":
        return "target_conflict"
    if reason == "blocked_critical":
        return "history_recovery"
    if tool in {"send_email", "send_direct_message", "send_channel_message", "share_file"}:
        return "dataflow_exfiltration"
    if tool in {"send_money", "schedule_transaction", "update_scheduled_transaction"}:
        return "provenance_conflict"
    return "safe_side_effect_control"


def write_bucket_csv(path: Path, labels: list[dict[str, Any]]) -> None:
    import csv

    fields = [
        "phase2_case_id",
        "source_ablation_case_id",
        "suite",
        "user_task_id",
        "injection_task_id",
        "selection_reason",
        "actiongraph_bucket",
        "primary_side_effect_tool",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(labels)


def resolve_full_e2e_dir(path: Path) -> Path:
    if path.exists():
        return path
    if FULL_E2E_FALLBACK.exists():
        return FULL_E2E_FALLBACK
    raise FileNotFoundError(path)


def load_rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def group_by_case(rows: list[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = case_key(row)
        grouped.setdefault(key, {"suite": key[0], "user_task_id": key[1], "injection_task_id": key[2]})
        grouped[key][str(row["method"])] = row
    return grouped


def case_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (str(row["suite"]), str(row["user_task_id"]), str(row["injection_task_id"]))


def add_cases(
    selected: dict[tuple[str, str, str], dict[str, Any]],
    sources: dict[str, list[str]],
    cases: list[dict[str, Any]],
    reason: str,
    full_dir: Path,
    model: str,
    attack: str,
) -> None:
    for case in sorted(cases, key=case_sort_key):
        key = (str(case["suite"]), str(case["user_task_id"]), str(case["injection_task_id"]))
        if key in selected:
            sources[selected[key]["phase2_case_id"]].append(reason)
            continue
        primary_tool = primary_side_effect_tool(case, full_dir)
        phase2_case_id = f"ablation_{key[0]}_{key[1]}_{key[2]}"
        selected[key] = {
            "phase2_case_id": phase2_case_id,
            "case_id": phase2_case_id,
            "suite": key[0],
            "user_task_id": key[1],
            "injection_task_id": key[2],
            "attack": attack,
            "model": model,
            "selection_reason": reason,
            "case_source_reason": reason,
            "source_methods": sorted(m for m in ("no_defense", "agentbrake_strict") if m in case),
            "has_full_trace": has_trace(case, full_dir, "agentbrake_strict"),
            "primary_side_effect_tool": primary_tool,
        }
        sources[phase2_case_id].append(reason)


def primary_side_effect_tool(case: dict[str, Any], full_dir: Path) -> str | None:
    for method in ("no_defense", "agentbrake_strict"):
        row = case.get(method) or {}
        trace = row.get("trace_file")
        if not trace:
            continue
        path = full_dir / str(trace)
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        for call in data.get("tool_calls") or []:
            tool = str(call.get("tool") or "")
            if tool in SIDE_EFFECT_TOOLS:
                return tool
    return None


def has_trace(case: dict[str, Any], full_dir: Path, method: str) -> bool:
    row = case.get(method) or {}
    trace = row.get("trace_file")
    return bool(trace and (full_dir / str(trace)).exists())


def blocked_sort_key(case: dict[str, Any]) -> tuple[Any, ...]:
    strict = case.get("agentbrake_strict", {})
    return (
        bool(strict.get("raw_agentdojo_user_task_success")),
        *case_sort_key(case),
    )


def case_sort_key(case: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(case["suite"]),
        str(case["user_task_id"]),
        str(case["injection_task_id"]),
        str(case.get("primary_side_effect_tool") or ""),
        str(case.get("case_source_reason") or ""),
    )


def plan_case_sort_key(case: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(case["suite"]),
        str(case["user_task_id"]),
        str(case["injection_task_id"]),
        str(case.get("primary_side_effect_tool") or ""),
        str(case.get("case_source_reason") or ""),
    )


def canonical_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def render_plan_md(plan: dict[str, Any], sources: dict[str, list[str]]) -> str:
    counts: dict[str, int] = defaultdict(int)
    for case in plan["cases"]:
        counts[str(case["selection_reason"])] += 1
    lines = [
        "# Qwen-Plus Ablation Diagnostic Case Plan",
        "",
        f"- case_count: {plan['case_count']}",
        f"- model: {plan['model']}",
        f"- attack: {plan['attack']}",
        f"- source_full_e2e_dir: {plan['source_full_e2e_dir']}",
        "",
        "## Selection Counts",
        "",
    ]
    for key in sorted(counts):
        lines.append(f"- {key}: {counts[key]}")
    lines += ["", f"- deduped_case_sources: {len(sources)}"]
    return "\n".join(lines) + "\n"


def render_gap_md(plan: dict[str, Any], target_size: int) -> str:
    status = "PASS" if plan["case_count"] == target_size else "FAIL"
    return "\n".join(
        [
            "# Qwen-Plus Ablation Diagnostic Gap Report",
            "",
            f"- status: {status}",
            f"- case_count: {plan['case_count']}",
            f"- target_size: {target_size}",
            f"- missing: {max(0, target_size - int(plan['case_count']))}",
        ]
    ) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
