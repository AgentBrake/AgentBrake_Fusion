from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


RISK_ORDER = [
    "Spread unsafe information / misinformation",
    "Lead to property loss",
    "Leak sensitive data / information",
    "Compromise availability",
    "Contribute to harmful / vulnerable code",
    "Violate law or ethics / damage society",
    "Lead to physical harm",
]

AGENTDOJO_LIKE_ENVS = {"Email", "Slack", "Bank", "Travel", "Calendar"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a fresh frozen Agent-SafetyBench evaluation plan.")
    parser.add_argument("--data", default="experiments/agent_safetybench/upstream/data/released_data.json")
    parser.add_argument(
        "--exclude-plans",
        nargs="*",
        default=[
            "experiments/agent_safetybench/case_plans/agentbrake_non_agentdojo_pilot_32.json",
            "experiments/agent_safetybench/case_plans/agentbrake_non_agentdojo_heldout_56.json",
        ],
    )
    parser.add_argument("--total", type=int, default=100)
    parser.add_argument("--plan-out", default="")
    parser.add_argument("--cases-out", default="")
    args = parser.parse_args()

    data = json.loads(Path(args.data).read_text(encoding="utf-8"))
    exclude_ids = _load_excluded_ids([Path(item) for item in args.exclude_plans])
    selected, bucket_ids = select_cases(data, exclude_ids, total=args.total)

    plan_out = Path(args.plan_out or f"experiments/agent_safetybench/case_plans/agentbrake_non_agentdojo_frozen_eval_{args.total}.json")
    cases_out = Path(args.cases_out or f"experiments/agent_safetybench/case_plans/agentbrake_non_agentdojo_frozen_eval_{args.total}_cases.json")
    plan = {
        "name": f"agentbrake_non_agentdojo_frozen_eval_{len(selected)}",
        "benchmark": "Agent-SafetyBench",
        "purpose": "Fresh frozen-rule evaluation subset after Pilot32 and heldout56 diagnostics.",
        "excluded_plans": args.exclude_plans,
        "excluded_case_count": len(exclude_ids),
        "selection_policy": {
            "total": args.total,
            "exclude_pilot32_and_heldout56": True,
            "require_tools": True,
            "balanced_across_7_risk_categories": True,
            "prefer_non_agentdojo_environments": True,
            "prefer_side_effect_or_sensitive_read_tools": True,
            "deterministic_sort": "risk quota, environment/tool diversity, case id",
            "frozen_rule_use": "Do not tune AgentBrake-Fusion rules on this split before reporting results.",
        },
        "risk_quota": {risk: len(ids) for risk, ids in bucket_ids.items()},
        "risk_case_ids": bucket_ids,
        "case_ids": [case["id"] for case in selected],
        "risk_counts": dict(Counter(risk for case in selected for risk in case.get("risks") or ["unknown"])),
    }
    plan_out.parent.mkdir(parents=True, exist_ok=True)
    plan_out.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    cases_out.write_text(json.dumps(selected, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(selected)} frozen evaluation cases")
    print(plan_out)
    print(cases_out)


def select_cases(data: list[dict[str, Any]], exclude_ids: set[int], *, total: int) -> tuple[list[dict[str, Any]], dict[str, list[int]]]:
    quotas = _risk_quotas(total)
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in data:
        cid = int(case.get("id"))
        if cid in exclude_ids or not _tools(case):
            continue
        for risk in case.get("risks") or []:
            if risk in RISK_ORDER:
                buckets[risk].append(case)

    selected: list[dict[str, Any]] = []
    bucket_ids: dict[str, list[int]] = {}
    used_ids: set[int] = set()
    env_counts: Counter[str] = Counter()
    tool_counts: Counter[str] = Counter()
    for risk in RISK_ORDER:
        quota = quotas[risk]
        picked: list[dict[str, Any]] = []
        for case in sorted(buckets[risk], key=lambda item: _case_score(item, env_counts, tool_counts)):
            cid = int(case.get("id"))
            if cid in used_ids:
                continue
            picked.append(case)
            used_ids.add(cid)
            env_counts.update(_envs(case))
            tool_counts.update(_tools(case))
            if len(picked) >= quota:
                break
        if len(picked) < quota:
            raise SystemExit(f"Risk bucket {risk!r} only selected {len(picked)} of {quota} requested cases")
        selected.extend(picked)
        bucket_ids[risk] = [int(case["id"]) for case in picked]

    if len(selected) != total:
        raise SystemExit(f"Selected {len(selected)} cases, expected {total}")
    return selected, bucket_ids


def _risk_quotas(total: int) -> dict[str, int]:
    base, remainder = divmod(total, len(RISK_ORDER))
    return {risk: base + (1 if idx < remainder else 0) for idx, risk in enumerate(RISK_ORDER)}


def _load_excluded_ids(paths: list[Path]) -> set[int]:
    excluded: set[int] = set()
    for path in paths:
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        excluded.update(int(case_id) for case_id in payload.get("case_ids") or [])
    return excluded


def _case_score(case: dict[str, Any], env_counts: Counter[str], tool_counts: Counter[str]) -> tuple[int, int, int, int]:
    envs = _envs(case)
    tools = _tools(case)
    non_agentdojo_bonus = -sum(1 for env in envs if env not in AGENTDOJO_LIKE_ENVS)
    effect_bonus = -sum(1 for tool in tools if _effectful_or_sensitive(tool))
    diversity_penalty = sum(env_counts[env] for env in envs) + sum(tool_counts[tool] for tool in tools)
    return (non_agentdojo_bonus, effect_bonus, diversity_penalty, int(case.get("id")))


def _envs(case: dict[str, Any]) -> list[str]:
    return [str(env.get("name")) for env in case.get("environments") or [] if env.get("name")]


def _tools(case: dict[str, Any]) -> list[str]:
    return [str(tool) for env in case.get("environments") or [] for tool in env.get("tools") or []]


def _effectful_or_sensitive(tool: str) -> bool:
    lowered = tool.lower()
    return any(
        token in lowered
        for token in (
            "send",
            "post",
            "share",
            "delete",
            "remove",
            "update",
            "write",
            "execute",
            "terminal",
            "allocate",
            "dispatch",
            "set_",
            "turn",
            "private",
            "patient",
            "sniff",
            "download",
            "click",
            "credential",
            "password",
            "traffic",
            "genetic",
            "medical",
            "health",
        )
    )


if __name__ == "__main__":
    main()
