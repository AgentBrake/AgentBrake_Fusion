from __future__ import annotations

import argparse
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
VARIANTS = (
    "rule_only",
    "no_binding",
    "no_recovery_guidance",
    "flatten_action_graph",
    "no_actiongraph_provenance_edges",
    "no_actiongraph_dataflow_edges",
    "no_actiongraph_history_edges",
)
ACTIONGRAPH_VARIANTS = (
    "flatten_action_graph",
    "no_actiongraph_provenance_edges",
    "no_actiongraph_dataflow_edges",
    "no_actiongraph_history_edges",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Qwen-Plus ablation diagnostic variants")
    parser.add_argument("--case-plan", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--model", default="qwen-plus")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--variants", nargs="+", default=list(VARIANTS))
    parser.add_argument("--confirmation-mode", default="strict_eval", choices=["strict_eval"])
    parser.add_argument("--save-full-trace", action="store_true")
    parser.add_argument("--trace-dir", type=Path, default=None)
    parser.add_argument("--parallel-variants", action="store_true")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    args = parser.parse_args()

    plan = json.loads(args.case_plan.read_text(encoding="utf-8-sig"))
    cases = list(plan["cases"])
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "raw").mkdir(parents=True, exist_ok=True)
    raw_runs = args.out_dir / "raw_runs"
    trace_root = args.trace_dir or (args.out_dir / "full_traces")
    python_bin = os.environ.get("PYTHON", "python")
    commands = build_commands(cases, args, raw_runs, trace_root, python_bin)
    plan_name = "run_plan_all_variants.json" if any(v in ACTIONGRAPH_VARIANTS for v in args.variants) else "run_plan.json"
    write_json(args.out_dir / plan_name, commands)

    failures: list[dict[str, Any]] = []
    completed: dict[str, list[str]] = {variant: [] for variant in args.variants}
    if args.parallel_variants:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = {pool.submit(run_one_item, item, args.skip_existing): item for item in commands}
            for future in as_completed(futures):
                item = futures[future]
                result = future.result()
                if result["completed"]:
                    completed[item["variant"]].append(result["raw_output"])
                else:
                    failures.append(result["failure"])
                    if args.fail_fast:
                        break
    else:
        result = run_items(commands, args.skip_existing, args.fail_fast)
        for item in result["completed_items"]:
            completed[item["variant"]].append(item["raw_output"])
        failures.extend(result["failures"])

    for variant, files in completed.items():
        write_json(args.out_dir / "raw" / f"{variant}.json", {"variant": variant, "raw_outputs": sorted(set(files))})
    manifest = {
        "experiment": "qwen_plus_actiongraph_ablation_diagnostic"
        if any(v in ACTIONGRAPH_VARIANTS for v in args.variants)
        else "qwen_plus_ablation_diagnostic",
        "case_plan": str(args.case_plan.as_posix()),
        "case_count": len(cases),
        "variants": list(args.variants),
        "parallel_variants": bool(args.parallel_variants),
        "workers": args.workers,
        "expected_run_count": len(cases) * len(args.variants),
        "completed_run_count": sum(len(set(files)) for files in completed.values()),
        "failure_count": len(failures),
        "failures": failures,
        "confirmation_mode": args.confirmation_mode,
        "save_full_trace": bool(args.save_full_trace),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    manifest_name = "run_manifest_all_variants.json" if any(v in ACTIONGRAPH_VARIANTS for v in args.variants) else "run_manifest.json"
    write_json(args.out_dir / manifest_name, manifest)
    write_json(args.out_dir / "ablation_run_failures.json", failures)
    return 1 if failures and args.fail_fast else 0


def run_one_item(item: dict[str, Any], skip_existing: bool) -> dict[str, Any]:
    out_file = Path(item["raw_output"])
    if skip_existing and out_file.exists():
        return {"completed": True, "raw_output": str(out_file.as_posix()), "failure": None}
    out_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(item["command"], cwd=ROOT, check=True, env=os.environ.copy())
    except subprocess.CalledProcessError as exc:
        return {
            "completed": False,
            "raw_output": str(out_file.as_posix()),
            "failure": {
                "case_id": item["case_id"],
                "variant": item["variant"],
                "returncode": exc.returncode,
                "raw_output": item["raw_output"],
            },
        }
    return {"completed": True, "raw_output": str(out_file.as_posix()), "failure": None}


def run_items(commands: list[dict[str, Any]], skip_existing: bool, fail_fast: bool) -> dict[str, Any]:
    failures: list[dict[str, Any]] = []
    completed: list[str] = []
    completed_items: list[dict[str, Any]] = []
    for item in commands:
        out_file = Path(item["raw_output"])
        if skip_existing and out_file.exists():
            completed.append(str(out_file.as_posix()))
            completed_items.append(item)
            continue
        out_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(item["command"], cwd=ROOT, check=True, env=os.environ.copy())
            completed.append(str(out_file.as_posix()))
            completed_items.append(item)
        except subprocess.CalledProcessError as exc:
            failure = {
                "case_id": item["case_id"],
                "variant": item["variant"],
                "returncode": exc.returncode,
                "raw_output": item["raw_output"],
            }
            failures.append(failure)
            if fail_fast:
                break
    return {"completed": completed, "completed_items": completed_items, "failures": failures}


def build_commands(
    cases: list[dict[str, Any]],
    args: argparse.Namespace,
    raw_runs: Path,
    trace_root: Path,
    python_bin: str,
) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    for case in cases:
        for variant in args.variants:
            if variant not in VARIANTS:
                raise ValueError(f"unsupported ablation variant: {variant}")
            case_id = str(case["phase2_case_id"])
            run_name = f"{case_id}_{variant}"
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
                "agentdojo_firewall",
                "--report-dir",
                str(raw_runs),
                "--run-name",
                run_name,
                "--user-tasks",
                str(case["user_task_id"]),
                "--injection-tasks",
                str(case["injection_task_id"]),
                "--confirmation-mode",
                args.confirmation_mode,
                "--ablation-profile",
                variant,
            ]
            if args.save_full_trace:
                command.extend(["--save-full-trace", "--trace-dir", str(trace_root / variant)])
            commands.append(
                {
                    "case_id": case_id,
                    "variant": variant,
                    "suite": case["suite"],
                    "raw_output": str((raw_runs / f"{run_name}.json").as_posix()),
                    "command": command,
                }
            )
    return commands


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
