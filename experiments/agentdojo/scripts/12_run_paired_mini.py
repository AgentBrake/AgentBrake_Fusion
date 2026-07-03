from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MANIFEST = ROOT / "experiments" / "agentdojo" / "configs" / "paired_mini_manifest.json"
DEFAULT_OUT = ROOT / "experiments" / "agentdojo" / "reports" / "paired_mini"

SUPPORTED_METHODS = {
    "no_defense": "none",
    "agentdojo_tool_filter": "tool_filter",
    "agentbrake_tool_firewall": "agentdojo_firewall",
}

OPTIONAL_METHODS = {
    "gateway_only": "agentbrake_gateway_only",
    "agentbrake_full": "agentdojo_firewall_full",
    "simple_denylist": "simple_denylist",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run paired AgentDojo mini benchmark from a shared manifest")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out-dir", "--out", dest="out_dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--model", default=None)
    parser.add_argument("--methods", default=None)
    parser.add_argument("--confirmation-mode", default=None)
    parser.add_argument("--save-full-trace", action="store_true")
    parser.add_argument("--trace-dir", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if args.model:
        manifest["model"] = args.model
    if args.methods:
        manifest["methods"] = [item.strip() for item in args.methods.split(",") if item.strip()]
    if args.confirmation_mode:
        method_options = dict(manifest.get("method_options") or {})
        for method in manifest.get("methods", []):
            if method.startswith("agentbrake_tool_firewall"):
                method_options.setdefault(method, {})["confirmation_mode"] = args.confirmation_mode
        manifest["method_options"] = method_options
    args.out_dir.mkdir(parents=True, exist_ok=True)
    plan = build_plan(manifest, args.out_dir, save_full_trace=args.save_full_trace, trace_dir=args.trace_dir)
    (args.out_dir / "paired_plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    if args.dry_run:
        print(args.out_dir / "paired_plan.json")
        return 0
    for command in plan:
        subprocess.run(command, cwd=ROOT, check=True)
    return 0


def build_plan(
    manifest: dict,
    out_dir: Path,
    *,
    save_full_trace: bool = False,
    trace_dir: Path | None = None,
) -> list[list[str]]:
    _validate_method_mapping(list(manifest["methods"]))
    commands: list[list[str]] = []
    for suite, suite_spec in manifest["suites"].items():
        for method in manifest["methods"]:
            command = [
                    sys.executable,
                    "-m",
                    "agentbrake.eval.agentdojo.runner.run_tool_firewall_eval",
                    "--suite",
                    suite,
                    "--model",
                    manifest["model"],
                    "--benchmark-version",
                    manifest["agentdojo_version"],
                    "--attack",
                    manifest["attack"],
                    "--defense",
                    SUPPORTED_METHODS[method],
                    "--report-dir",
                    str(out_dir),
                    "--run-name",
                    f"{suite}_{method}_{manifest['attack']}",
                ]
            user_tasks = [str(item) for item in suite_spec.get("user_tasks", [])]
            injection_tasks = [str(item) for item in suite_spec.get("injection_tasks", [])]
            if user_tasks:
                command.extend(["--user-tasks", *user_tasks])
            if injection_tasks:
                command.extend(["--injection-tasks", *injection_tasks])
            options = (manifest.get("method_options") or {}).get(method, {})
            if options.get("confirmation_mode"):
                command.extend(["--confirmation-mode", str(options["confirmation_mode"])])
            if save_full_trace:
                command.append("--save-full-trace")
                command.extend(["--trace-dir", str(trace_dir or (out_dir / "full_traces"))])
            commands.append(command)
    return commands


def _validate_method_mapping(methods: list[str]) -> None:
    unsupported = [method for method in methods if method not in SUPPORTED_METHODS]
    if unsupported:
        raise ValueError(f"Unsupported paired benchmark methods require separate runner implementations: {unsupported}")
    mapped = {method: SUPPORTED_METHODS[method] for method in methods}
    reverse: dict[str, list[str]] = {}
    for method, defense in mapped.items():
        reverse.setdefault(defense, []).append(method)
    duplicates = {defense: names for defense, names in reverse.items() if len(names) > 1}
    if duplicates:
        raise ValueError(f"Paired benchmark methods map to the same defense: {duplicates}")


if __name__ == "__main__":
    raise SystemExit(main())
