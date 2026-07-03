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
    parser = argparse.ArgumentParser(description="Build a held-out Agent-SafetyBench plan after Pilot32 rule development.")
    parser.add_argument("--data", default="experiments/agent_safetybench/upstream/data/released_data.json")
    parser.add_argument("--exclude-plan", default="experiments/agent_safetybench/case_plans/agentbrake_non_agentdojo_pilot_32.json")
    parser.add_argument("--per-risk", type=int, default=8)
    parser.add_argument("--plan-out", default="experiments/agent_safetybench/case_plans/agentbrake_non_agentdojo_heldout_56.json")
    parser.add_argument("--cases-out", default="experiments/agent_safetybench/case_plans/agentbrake_non_agentdojo_heldout_56_cases.json")
    args = parser.parse_args()

    data = json.loads(Path(args.data).read_text(encoding="utf-8"))
    exclude = set(json.loads(Path(args.exclude_plan).read_text(encoding="utf-8"))["case_ids"])
    selected = select_cases(data, exclude, per_risk=args.per_risk)
    plan = {
        "name": f"agentbrake_non_agentdojo_heldout_{len(selected)}",
        "benchmark": "Agent-SafetyBench",
        "purpose": "Held-out subset for checking whether the frozen AgentBrake-Fusion ASB rules generalize beyond the Pilot32 development set.",
        "excluded_development_plan": str(args.exclude_plan),
        "selection_policy": {
            "exclude_pilot32": True,
            "per_risk": args.per_risk,
            "require_tools": True,
            "prefer_non_agentdojo_environments": True,
            "prefer_side_effect_or_sensitive_read_tools": True,
            "deterministic_sort": "risk bucket score, environment/tool diversity, case id",
        },
        "case_ids": [case["id"] for case in selected],
        "risk_counts": dict(Counter(risk for case in selected for risk in case.get("risks") or ["unknown"])),
        "notes": [
            "This set is selected before running AgentBrake-Fusion on it and should not be used for rule tuning.",
            "The selection intentionally avoids Pilot32 case ids and favors non-AgentDojo environments and tool effects.",
        ],
    }
    Path(args.plan_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.plan_out).write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    Path(args.cases_out).write_text(json.dumps(selected, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(selected)} held-out cases")
    print(args.plan_out)
    print(args.cases_out)


def select_cases(data: list[dict[str, Any]], exclude: set[int], *, per_risk: int) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in data:
        if int(case.get("id")) in exclude:
            continue
        if not _tools(case):
            continue
        for risk in case.get("risks") or []:
            if risk in RISK_ORDER:
                buckets[risk].append(case)

    selected: list[dict[str, Any]] = []
    used_ids: set[int] = set()
    env_counts: Counter[str] = Counter()
    tool_counts: Counter[str] = Counter()
    for risk in RISK_ORDER:
        picked = []
        for case in sorted(buckets[risk], key=lambda item: _case_score(item, env_counts, tool_counts)):
            cid = int(case.get("id"))
            if cid in used_ids:
                continue
            picked.append(case)
            used_ids.add(cid)
            env_counts.update(_envs(case))
            tool_counts.update(_tools(case))
            if len(picked) >= per_risk:
                break
        if len(picked) < per_risk:
            raise SystemExit(f"Risk bucket {risk!r} only selected {len(picked)} cases")
        selected.extend(picked)
    return selected


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
        )
    )


if __name__ == "__main__":
    main()
