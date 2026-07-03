"""AgentDojo evaluation CLI registration."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def register_eval_agentdojo(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    eval_parser = subparsers.add_parser("eval", help="Evaluation commands")
    eval_sub = eval_parser.add_subparsers(dest="eval_cmd", required=True)

    agentdojo = eval_sub.add_parser("agentdojo", help="AgentDojo evaluation commands")
    agentdojo_sub = agentdojo.add_subparsers(dest="agentdojo_cmd", required=True)

    inventory = agentdojo_sub.add_parser("inventory", help="Summarize AgentDojo tool taxonomy coverage")
    inventory.add_argument("--tools", nargs="*", default=[])
    inventory.set_defaults(func=cmd_inventory)

    run = agentdojo_sub.add_parser("run", help="Run an AgentDojo evaluation")
    run.add_argument("--mode", choices=["baseline", "gateway-only", "tool-firewall"], default="tool-firewall")
    run.add_argument("--suite", default="travel")
    run.add_argument("--model", default="local")
    run.add_argument("--model-id")
    run.add_argument("--attack", default="none")
    run.add_argument("--limit", type=int)
    run.add_argument("--logdir", type=Path)
    run.add_argument("--report-dir", type=Path, default=Path("experiments/agentdojo/reports/runs"))
    run.add_argument("--repo-root", type=Path, default=Path.cwd())
    run.set_defaults(func=cmd_run)

    summarize = agentdojo_sub.add_parser("summarize", help="Summarize AgentDojo reports")
    summarize.add_argument("--report-dir", type=Path, default=Path("experiments/agentdojo/reports/runs"))
    summarize.set_defaults(func=cmd_summarize)

    profile = agentdojo_sub.add_parser("profile", help="Show AgentDojo report files")
    profile.add_argument("--report-dir", type=Path, default=Path("experiments/agentdojo/reports"))
    profile.set_defaults(func=cmd_profile)


def cmd_inventory(args: argparse.Namespace) -> int:
    from agentbrake.eval.agentdojo.tool_taxonomy import coverage_report

    print(json.dumps(coverage_report(args.tools), ensure_ascii=False, indent=2))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from agentbrake.eval.agentdojo import require_agentdojo
    from agentbrake.eval.agentdojo.runner.run_tool_firewall_eval import run_suite

    require_agentdojo()
    defense = {"baseline": "none", "gateway-only": "agentbrake_toolgate", "tool-firewall": "agentdojo_firewall"}[args.mode]
    summary = run_suite(
        args.suite,
        args.model,
        defense,
        model_id=args.model_id,
        attack=args.attack,
        limit=args.limit,
        logdir=args.logdir,
        report_dir=args.report_dir,
        repo_root=args.repo_root,
        run_name=f"{args.suite}_{args.mode}_{args.attack}",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    files = sorted(args.report_dir.glob("*.json")) if args.report_dir.exists() else []
    summaries: list[dict[str, Any]] = []
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        summaries.append(
            {
                "file": str(path),
                "run_name": data.get("run_name"),
                "suite": data.get("suite"),
                "defense": data.get("defense"),
                "utility_under_attack": data.get("utility_under_attack"),
                "security": data.get("security"),
                "targeted_asr": data.get("targeted_asr"),
            }
        )
    print(json.dumps({"reports": summaries}, ensure_ascii=False, indent=2))
    return 0


def cmd_profile(args: argparse.Namespace) -> int:
    files = sorted(str(path) for path in args.report_dir.rglob("*") if path.is_file()) if args.report_dir.exists() else []
    print(json.dumps({"report_dir": str(args.report_dir), "files": files}, ensure_ascii=False, indent=2))
    return 0

