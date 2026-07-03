from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_FULL_PLAN = (
    ROOT
    / "experiments"
    / "agentdojo"
    / "reports"
    / "deepseekv4_flash"
    / "e2e_full_agentdojo"
    / "full_agentdojo_case_plan_frozen.json"
)
DEFAULT_FORMAL_PLAN = (
    ROOT
    / "experiments"
    / "agentdojo"
    / "reports"
    / "cross_model"
    / "qwen_plus"
    / "e2e_formal_105"
    / "case_plan_frozen.json"
)
DEFAULT_MANIFEST = (
    ROOT
    / "experiments"
    / "agentdojo"
    / "reports"
    / "cross_model"
    / "qwen_plus"
    / "replay_cases"
    / "manifest_agentdojo_derived.json"
)
DEFAULT_OUT_DIR = (
    ROOT
    / "experiments"
    / "agentdojo"
    / "reports"
    / "cross_model"
    / "qwen_plus"
    / "replay_gap_closure"
)

SUITE_PRIORITY = ("workspace", "travel", "banking", "slack")
TARGET_SAFE = 60
TARGET_UNSAFE = 60


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan Qwen-Plus same-model no_defense cases for replay gap closure")
    parser.add_argument("--full-plan", type=Path, default=DEFAULT_FULL_PLAN)
    parser.add_argument("--formal-plan", type=Path, default=DEFAULT_FORMAL_PLAN)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--planned-cases", type=int, default=260)
    args = parser.parse_args()

    full_plan = read_json(args.full_plan)
    formal_plan = read_json(args.formal_plan)
    manifest = read_json(args.manifest)
    already_seen = {(case["suite"], case["user_task_id"], case["injection_task_id"]) for case in formal_plan.get("cases", [])}
    selected = select_cases(full_plan.get("cases", []), already_seen, limit=args.planned_cases)

    current_safe = int(manifest.get("safe_case_count", 0) or 0)
    current_unsafe = int(manifest.get("unsafe_case_count", 0) or 0)
    plan = {
        "schema_version": "agentbrake_qwen_replay_gap_plan_v1",
        "model_key": "qwen_plus",
        "model_id": "qwen-plus",
        "provider": "alibaba_dashscope",
        "adapter": "openai_compatible_chat",
        "attack": "important_instructions",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_unsafe_count": TARGET_UNSAFE,
        "target_safe_count": TARGET_SAFE,
        "minimum_unsafe_count": 50,
        "minimum_safe_count": 50,
        "current_unsafe_count": current_unsafe,
        "current_safe_count": current_safe,
        "current_trace_missing_count": int(manifest.get("trace_missing_count", 0) or 0),
        "shortfall_to_minimum": {
            "unsafe": max(0, 50 - current_unsafe),
            "safe": max(0, 50 - current_safe),
        },
        "shortfall_to_target": {
            "unsafe": max(0, TARGET_UNSAFE - current_unsafe),
            "safe": max(0, TARGET_SAFE - current_safe),
        },
        "selection_policy": "same_model_no_defense_full_trace_expansion",
        "no_manual_cases": True,
        "no_deepseek_trace_mixing": True,
        "source_full_plan": posix(args.full_plan),
        "excluded_existing_formal_pairs": len(already_seen),
        "case_count": len(selected),
        "planned_no_defense_cases": selected,
        "cases": selected,
        "by_suite": dict(sorted(Counter(case["suite"] for case in selected).items())),
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.out_dir / "qwen_replay_gap_plan.json", plan)
    (args.out_dir / "qwen_replay_gap_plan.md").write_text(render_md(plan), encoding="utf-8")
    print(args.out_dir / "qwen_replay_gap_plan.json")
    return 0


def select_cases(cases: list[dict[str, Any]], already_seen: set[tuple[str, str, str]], *, limit: int) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = {suite: [] for suite in SUITE_PRIORITY}
    for case in cases:
        key = (str(case.get("suite")), str(case.get("user_task_id")), str(case.get("injection_task_id")))
        if key in already_seen:
            continue
        suite = str(case.get("suite"))
        if suite in buckets:
            buckets[suite].append(normalize_case(case))

    selected: list[dict[str, Any]] = []
    target_by_suite = {"workspace": 95, "travel": 65, "banking": 60, "slack": 40}
    for suite in SUITE_PRIORITY:
        selected.extend(buckets[suite][: target_by_suite[suite]])
    if len(selected) < limit:
        used = {(case["suite"], case["user_task_id"], case["injection_task_id"]) for case in selected}
        for suite in SUITE_PRIORITY:
            for case in buckets[suite]:
                key = (case["suite"], case["user_task_id"], case["injection_task_id"])
                if key in used:
                    continue
                selected.append(case)
                used.add(key)
                if len(selected) >= limit:
                    break
            if len(selected) >= limit:
                break
    return selected[:limit]


def normalize_case(case: dict[str, Any]) -> dict[str, Any]:
    suite = str(case["suite"])
    user_task_id = str(case["user_task_id"])
    injection_task_id = str(case["injection_task_id"])
    case_id = f"qwen_gap_{suite}_{user_task_id}_{injection_task_id}"
    return {
        "case_id": case_id,
        "phase2_case_id": case_id,
        "suite": suite,
        "user_task_id": user_task_id,
        "injection_task_id": injection_task_id,
        "attack": "important_instructions",
        "source": "agentdojo_full_distribution_pair",
        "selection_reason": "qwen_replay_gap_same_model_no_defense_expansion",
    }


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def posix(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def render_md(plan: dict[str, Any]) -> str:
    lines = [
        "# Qwen Replay Gap Closure Plan",
        "",
        f"- model: {plan['model_id']}",
        f"- attack: {plan['attack']}",
        f"- current unsafe/safe: {plan['current_unsafe_count']} / {plan['current_safe_count']}",
        f"- minimum unsafe/safe: {plan['minimum_unsafe_count']} / {plan['minimum_safe_count']}",
        f"- target unsafe/safe: {plan['target_unsafe_count']} / {plan['target_safe_count']}",
        f"- planned no_defense cases: {plan['case_count']}",
        f"- selection_policy: {plan['selection_policy']}",
        f"- no_manual_cases: {str(plan['no_manual_cases']).lower()}",
        f"- no_deepseek_trace_mixing: {str(plan['no_deepseek_trace_mixing']).lower()}",
        "",
        "## By Suite",
        "",
        "| suite | planned_cases |",
        "| --- | ---: |",
    ]
    for suite, count in plan["by_suite"].items():
        lines.append(f"| {suite} | {count} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
