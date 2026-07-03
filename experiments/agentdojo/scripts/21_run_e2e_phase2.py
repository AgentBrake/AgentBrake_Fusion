from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT = ROOT / "experiments" / "agentdojo" / "reports" / "deepseekv4_flash" / "e2e_phase2"

METHODS = {
    "no_defense": {"defense": "none", "confirmation_mode": None},
    "tool_filter": {"defense": "tool_filter", "confirmation_mode": None},
    "agentbrake_strict": {"defense": "agentdojo_firewall", "confirmation_mode": "strict_eval"},
    "agentbrake_gateway_eval": {"defense": "agentdojo_firewall", "confirmation_mode": "gateway_eval"},
    "agentbrake_oracle_user_eval": {"defense": "agentdojo_firewall", "confirmation_mode": "oracle_user_eval"},
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AgentDojo Phase 2 E2E task pairs")
    parser.add_argument("--case-plan", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--methods", nargs="+", default=["no_defense", "agentbrake_strict", "agentbrake_gateway_eval", "agentbrake_oracle_user_eval"])
    parser.add_argument("--suites", nargs="*", default=None)
    parser.add_argument("--max-cases-per-suite", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--save-full-trace", action="store_true")
    parser.add_argument("--trace-dir", type=Path, default=None)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    plan = json.loads(args.case_plan.read_text(encoding="utf-8"))
    cases = select_cases(plan["cases"], suites=args.suites, max_cases_per_suite=args.max_cases_per_suite)
    commands = build_commands(cases, args)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "phase2_run_plan.json").write_text(json.dumps(commands, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.dry_run:
        dry_run = {
            "case_count": len(cases),
            "method_count": len(args.methods),
            "estimated_run_count": len(commands),
            "save_full_trace": bool(args.save_full_trace),
            "run_plan": "phase2_run_plan.json",
        }
        (args.out_dir / "dry_run_summary.json").write_text(json.dumps(dry_run, indent=2, ensure_ascii=False), encoding="utf-8")
        (args.out_dir / "dry_run_summary.md").write_text(render_dry_run_md(dry_run), encoding="utf-8")
        print(args.out_dir / "phase2_run_plan.json")
        return 0

    failures: list[dict[str, Any]] = []
    for item in commands:
        out_file = Path(item["raw_output"])
        if args.skip_existing and out_file.exists():
            continue
        out_file.parent.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        if args.seed is not None:
            env["PYTHONHASHSEED"] = str(args.seed)
        try:
            subprocess.run(item["command"], cwd=ROOT, check=True, env=env)
        except subprocess.CalledProcessError as exc:
            failure = {"phase2_case_id": item["case_id"], "method": item["method"], "returncode": exc.returncode}
            failures.append(failure)
            if args.fail_fast:
                break
    (args.out_dir / "phase2_run_failures.json").write_text(json.dumps(failures, indent=2), encoding="utf-8")
    return 1 if failures and args.fail_fast else 0


def select_cases(cases: list[dict[str, Any]], *, suites: list[str] | None, max_cases_per_suite: int | None) -> list[dict[str, Any]]:
    suite_filter = set(suites or [])
    counts: dict[str, int] = {}
    selected: list[dict[str, Any]] = []
    for case in cases:
        suite = str(case["suite"])
        if suite_filter and suite not in suite_filter:
            continue
        if max_cases_per_suite is not None and counts.get(suite, 0) >= max_cases_per_suite:
            continue
        selected.append(case)
        counts[suite] = counts.get(suite, 0) + 1
    return selected


def build_commands(cases: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    raw_dir = args.out_dir / "raw_runs"
    trace_root = args.trace_dir or (args.out_dir / "full_traces")
    python_bin = os.environ.get("PYTHON", "python")
    for method in args.methods:
        if method not in METHODS:
            raise ValueError(f"unsupported method: {method}")
        method_spec = METHODS[method]
        for case in cases:
            case_id = str(case.get("phase2_case_id") or case.get("case_id"))
            if not case_id or case_id == "None":
                raise ValueError(f"case is missing phase2_case_id/case_id: {case}")
            run_name = f"{case_id}_{method}"
            command = [
                python_bin,
                "-m",
                "agentbrake.eval.agentdojo.runner.run_tool_firewall_eval",
                "--suite",
                str(case["suite"]),
                "--model",
                args.model,
                "--benchmark-version",
                "v1.2.2",
                "--attack",
                args.attack,
                "--defense",
                str(method_spec["defense"]),
                "--report-dir",
                str(raw_dir),
                "--run-name",
                run_name,
                "--user-tasks",
                str(case["user_task_id"]),
                "--injection-tasks",
                str(case["injection_task_id"]),
            ]
            if method_spec["confirmation_mode"]:
                command.extend(["--confirmation-mode", str(method_spec["confirmation_mode"])])
            if args.save_full_trace:
                command.append("--save-full-trace")
                command.extend(["--trace-dir", str(trace_root / method)])
            commands.append(
                {
                    "phase2_case_id": case_id,
                    "case_id": case_id,
                    "suite": case["suite"],
                    "method": method,
                    "raw_output": str((raw_dir / f"{run_name}.json").as_posix()),
                    "command": command,
                }
            )
    return commands


def render_dry_run_md(summary: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# AgentDojo E2E Dry Run",
            "",
            f"- case_count: {summary['case_count']}",
            f"- method_count: {summary['method_count']}",
            f"- estimated_run_count: {summary['estimated_run_count']}",
            f"- save_full_trace: {summary['save_full_trace']}",
            f"- run_plan: {summary['run_plan']}",
        ]
    ) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
