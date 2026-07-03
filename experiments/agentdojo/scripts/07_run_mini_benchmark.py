from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentbrake.eval.agentdojo.runner.run_tool_firewall_eval import run_suite

ROOT = Path(__file__).resolve().parents[3]
REPORT_DIR = ROOT / "experiments" / "agentdojo" / "reports"
RUN_DIR = REPORT_DIR / "runs"


def run_suite_limit(*, suite: str, model: str, attack: str, limit: int) -> dict[str, object]:
    logdir = ROOT / "experiments" / "agentdojo" / "logs" / f"mini_{suite}"
    return run_suite(
        suite,
        model,
        "agentdojo_firewall",
        attack=attack,
        limit=limit,
        logdir=logdir,
        report_dir=RUN_DIR,
        run_name=f"{suite}_mini_agentdojo_firewall_{attack}",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--limit", type=int, default=2)
    parser.add_argument("--suites", nargs="+", default=["travel", "banking"])
    args = parser.parse_args()

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    RUN_DIR.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, object]] = []
    for suite in args.suites:
        result = run_suite_limit(suite=suite, model=args.model, attack=args.attack, limit=args.limit)
        results.append(result)

    payload = {"model": args.model, "attack": args.attack, "limit": args.limit, "results": results}
    (REPORT_DIR / "mini_benchmark.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = ["# Mini Benchmark", ""]
    for item in results:
        fw = item.get("agentdojo_firewall_audit_summary") or {}
        lines.extend(
            [
                f"## {item['suite']}",
                "",
                f"- Utility Under Attack: {item['utility_under_attack']:.3f}",
                f"- Security: {item['security']:.3f}",
                f"- ASR: {item['targeted_asr']:.3f}",
                f"- registered_tool_rate: {fw.get('registered_tool_rate', 0.0):.3f}",
                f"- unknown_tool_rate: {fw.get('unknown_tool_rate', 0.0):.3f}",
                f"- total_tool_calls_gated: {fw.get('total_tool_calls_gated', 0)}",
                f"- blocked_tool_calls: {fw.get('blocked_tool_calls', 0)}",
                f"- policy_p50_ms: {fw.get('policy_p50_ms', 0.0):.3f}",
                f"- policy_p95_ms: {fw.get('policy_p95_ms', 0.0):.3f}",
                f"- rule_hit_counts: {fw.get('rule_hit_counts', {})}",
                "",
            ]
        )
    (REPORT_DIR / "mini_benchmark.md").write_text("\n".join(lines), encoding="utf-8")
    print((REPORT_DIR / "mini_benchmark.md"))


if __name__ == "__main__":
    main()



