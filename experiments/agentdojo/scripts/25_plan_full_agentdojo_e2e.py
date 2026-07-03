from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentdojo.task_suite.load_suites import get_suite

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT = ROOT / "experiments" / "agentdojo" / "reports" / "deepseekv4_flash" / "e2e_full_agentdojo"
SUITES = ("banking", "slack", "travel", "workspace")
METHODS = ("no_defense", "tool_filter", "agentbrake_strict", "agentbrake_gateway_eval", "agentbrake_oracle_user_eval")


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan full-distribution AgentDojo Phase 2.2 E2E cases")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--suites", nargs="+", default=list(SUITES))
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    plan = build_plan(args.benchmark_version, tuple(args.suites))
    plan_path = args.out_dir / "full_agentdojo_case_plan.json"
    write_json(plan_path, plan)
    digest = sha256_file(plan_path)
    (args.out_dir / "full_agentdojo_case_plan.sha256").write_text(f"{digest}  full_agentdojo_case_plan.json\n", encoding="utf-8")
    (args.out_dir / "full_agentdojo_case_plan_rationale.md").write_text(render_rationale(plan), encoding="utf-8")
    print(plan_path)
    return 0


def build_plan(benchmark_version: str, suites: tuple[str, ...]) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    by_suite: dict[str, dict[str, int]] = {}
    for suite_name in suites:
        suite = get_suite(benchmark_version, suite_name)
        user_task_ids = sorted(str(task_id) for task_id in suite.user_tasks)
        injection_task_ids = sorted(str(task_id) for task_id in suite.injection_tasks)
        by_suite[suite_name] = {
            "user_task_count": len(user_task_ids),
            "injection_task_count": len(injection_task_ids),
            "case_count": len(user_task_ids) * len(injection_task_ids),
        }
        for user_task_id in user_task_ids:
            for injection_task_id in injection_task_ids:
                case_id = f"full_{suite_name}_{user_task_id}_{injection_task_id}"
                cases.append(
                    {
                        "case_id": case_id,
                        "phase2_case_id": case_id,
                        "suite": suite_name,
                        "user_task_id": user_task_id,
                        "injection_task_id": injection_task_id,
                        "selection_reason": "full_distribution_all_available_agentdojo_pairs",
                    }
                )
    return {
        "experiment_type": "agentdojo_e2e_full_distribution",
        "phase": "phase2.2",
        "benchmark_version": benchmark_version,
        "model": "deepseek-v4-flash",
        "attack": "important_instructions",
        "mode": "full_agentdojo",
        "plan_frozen": True,
        "suites": list(suites),
        "methods": list(METHODS),
        "case_count": len(cases),
        "planned_run_count": len(cases) * len(METHODS),
        "by_suite": by_suite,
        "cases": cases,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def render_rationale(plan: dict[str, Any]) -> str:
    lines = [
        "# Full AgentDojo E2E Case Plan Rationale",
        "",
        "This frozen plan enumerates every available user-task and injection-task pair for the selected AgentDojo suites.",
        "",
        f"- benchmark_version: {plan['benchmark_version']}",
        f"- case_count: {plan['case_count']}",
        f"- method_count: {len(plan['methods'])}",
        f"- planned_run_count: {plan['planned_run_count']}",
        "",
        "| suite | user_tasks | injection_tasks | cases |",
        "|---|---:|---:|---:|",
    ]
    for suite, stats in plan["by_suite"].items():
        lines.append(f"| {suite} | {stats['user_task_count']} | {stats['injection_task_count']} | {stats['case_count']} |")
    lines.extend(["", "Methods: " + ", ".join(plan["methods"])])
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
