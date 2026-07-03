"""Clean AgentDojo firewall benchmark entrypoint.

This module is the preferred runner for AgentDojo firewall experiments. It uses
AgentDojo's official suite execution and scoring while inserting
AgentDojoToolFirewall before every tool call through the runtime wrapper.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from agentdojo.attacks.attack_registry import load_attack
from agentdojo.logging import OutputLogger, TraceLogger
from agentdojo.task_suite.load_suites import get_suite

from agentbrake.eval.agentdojo.adapters.pipeline_wrapper import AgentBrakeAgentDojoContext
from agentbrake.eval.agentdojo.runner.run_tool_firewall_eval import (
    _infer_authorized_tools_and_categories,
    _run_agentdojo_task_with_retries,
    build_llm,
    build_pipeline,
)

from ..compat.types import AgentDojoDefenseMode, SanitizeMode
from ..gate.tool_firewall import summarize_agentdojo_firewall_audit


def main() -> None:
    args = parse_args()
    summary = run_benchmark(
        suite_name=args.suite,
        model=_normalize_model(args.model),
        defense=args.defense,
        attack=args.attack,
        limit=args.limit,
        mode=args.mode,
        sanitize_mode=args.sanitize_mode,
        out_dir=args.out_dir,
        benchmark_version=args.benchmark_version,
        max_iters=args.max_iters,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False, default=str))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run AgentDojo benchmark with AgentBrake-Fusion AgentDojo firewall")
    parser.add_argument("--suite", required=True, choices=["travel", "banking", "slack", "workspace", "workspace_plus"])
    parser.add_argument("--model", required=True)
    parser.add_argument("--defense", default="agentdojo_firewall", choices=["none", "tool_filter", "gateway_only", "agentdojo_firewall"])
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--mode", choices=["fair", "oracle_user", "oracle_full"], default="fair")
    parser.add_argument("--sanitize-mode", choices=["off", "label", "soft", "hard"], default="soft")
    parser.add_argument("--out-dir", type=Path, default=Path("experiments/agentdojo/reports/tool_firewall"))
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--max-iters", type=int, default=15)
    return parser.parse_args()


def run_benchmark(
    *,
    suite_name: str,
    model: str,
    defense: str,
    attack: str,
    limit: int | None,
    mode: AgentDojoDefenseMode,
    sanitize_mode: SanitizeMode,
    out_dir: Path,
    benchmark_version: str,
    max_iters: int,
) -> dict[str, Any]:
    started = time.perf_counter()
    out_dir.mkdir(parents=True, exist_ok=True)
    report_dir = out_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    suite = get_suite(benchmark_version, suite_name)
    llm, llm_name = build_llm(model, None, "tool")
    pipeline_defense = (
        "agentdojo_firewall" if defense == "agentdojo_firewall" else ("agentbrake_toolgate" if defense == "gateway_only" else defense)
    )
    if pipeline_defense == "agentbrake_toolgate":
        raise SystemExit(
            "gateway_only is preserved as a compatibility label; use agentbrake.eval.agentdojo.run_toolgate_eval for legacy gateway runs."
        )
    pipeline = build_pipeline(
        pipeline_defense,
        llm,
        None,
        system_message="You are a helpful assistant.",
        max_iters=max_iters,
    )
    if hasattr(pipeline, "firewall"):
        pipeline.firewall.sanitize_mode = sanitize_mode
        pipeline.firewall.state.sanitize_mode = sanitize_mode
    attack_obj = load_attack(attack, suite, pipeline)

    user_tasks = list(suite.user_tasks.values())
    if limit is not None:
        user_tasks = user_tasks[:limit]
    injection_ids = list(suite.injection_tasks.keys())
    if limit is not None:
        injection_ids = injection_ids[:limit]

    utility_results: dict[str, bool] = {}
    security_results: dict[str, bool] = {}
    per_run: list[dict[str, Any]] = []

    with OutputLogger(str(out_dir)):
        for user_task in user_tasks:
            user_task_id = str(getattr(user_task, "ID", "user_task"))
            for injection_task_id in injection_ids:
                injection_task = suite.get_injection_task_by_id(injection_task_id)
                injections = attack_obj.attack(user_task, injection_task)
                allowed_tools: list[str] = []
                allowed_categories: list[str] = []
                if mode in {"oracle_user", "oracle_full"}:
                    allowed_tools, allowed_categories = _infer_authorized_tools_and_categories(suite_name, suite, user_task)
                attack_goal_signatures: list[str] = []
                if mode == "oracle_full":
                    attack_goal_signatures = [
                        str(getattr(injection_task, "GOAL", "") or ""),
                        str(getattr(injection_task, "PROMPT", "") or ""),
                    ]
                if hasattr(pipeline, "set_context"):
                    pipeline.set_context(
                        AgentBrakeAgentDojoContext(
                            suite=suite_name,
                            user_task_id=user_task_id,
                            injection_task_id=str(injection_task_id),
                            task_instruction=getattr(user_task, "PROMPT", None),
                            injection_instruction=None if mode == "fair" else getattr(injection_task, "PROMPT", None),
                            attack_goal=None if mode != "oracle_full" else getattr(injection_task, "GOAL", None),
                            attack_goal_signatures=attack_goal_signatures,
                            source_ids=list(injections.keys()),
                            source_has_untrusted=bool(injections),
                            untrusted_observation_seen=bool(injections),
                            allowed_tools=allowed_tools,
                            allowed_tool_categories=allowed_categories,
                            run_id=f"{suite_name}-{user_task_id}-{injection_task_id}",
                            metadata={"defense_mode": mode, "sanitize_mode": sanitize_mode},
                        )
                    )
                with TraceLogger(
                    delegate=OutputLogger(str(out_dir)),
                    suite_name=suite.name,
                    user_task_id=user_task_id,
                    injection_task_id=str(injection_task_id),
                    injections=injections,
                    attack_type=attack_obj.name,
                    pipeline_name=getattr(pipeline, "name", llm_name),
                    benchmark_version=benchmark_version,
                ) as logger:
                    utility, security = _run_agentdojo_task_with_retries(suite, pipeline, user_task, injection_task, injections)
                    logger.set_contextarg("utility", utility)
                    logger.set_contextarg("security", security)
                sample_key = f"{user_task_id}::{injection_task_id}"
                utility_results[sample_key] = bool(utility)
                security_results[sample_key] = bool(security)
                per_run.append(
                    {
                        "user_task_id": user_task_id,
                        "injection_task_id": str(injection_task_id),
                        "utility": bool(utility),
                        "security": bool(security),
                    }
                )

    runtime_sec = time.perf_counter() - started
    utility_score = _avg_bool(utility_results.values())
    targeted_asr = _avg_bool(security_results.values())
    security_score = 1.0 - targeted_asr
    secure_utility = _avg_bool(
        bool(utility_results.get(key)) and not bool(security_results.get(key)) for key in utility_results
    )
    audit = summarize_agentdojo_firewall_audit(getattr(getattr(pipeline, "firewall", None), "audit_events", []) or [])
    summary = {
        "run_name": out_dir.name,
        "suite": suite_name,
        "benchmark_version": benchmark_version,
        "model": model,
        "defense": defense,
        "attack": attack,
        "mode": mode,
        "sanitize_mode": sanitize_mode,
        "oracle_warning": _mode_warning(mode),
        "total_runtime_sec": runtime_sec,
        "total_runtime_min": runtime_sec / 60.0,
        "utility_results": utility_results,
        "security_results": security_results,
        "metric_schema_version": "agentdojo_metrics_v2",
        "utility_under_attack": utility_score,
        "user_utility": utility_score,
        "security": security_score,
        "security_rate": security_score,
        "targeted_asr": targeted_asr,
        "secure_utility": secure_utility,
        "per_run": per_run,
        "agentdojo_firewall_audit_summary": audit,
        "tool_gate_decision_count": audit.get("tool_gate_decision_count", 0),
        "blocked_tool_calls": audit.get("blocked_tool_calls", 0),
        "registered_tool_rate": audit.get("registered_tool_rate", 0.0),
        "unknown_tool_rate": audit.get("unknown_tool_rate", 0.0),
        "rule_hit_counts": audit.get("rule_hit_counts", {}),
        "policy_latency_ms": {
            "p50": audit.get("policy_p50_ms", 0.0),
            "p95": audit.get("policy_p95_ms", 0.0),
        },
    }
    json_path = report_dir / f"{suite_name}_{defense}_{attack}_{mode}.json"
    md_path = report_dir / f"{suite_name}_{defense}_{attack}_{mode}.md"
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    return summary


def render_markdown(summary: dict[str, Any]) -> str:
    audit = summary.get("agentdojo_firewall_audit_summary") or {}
    lines = [
        "# AgentDojo Firewall Benchmark",
        "",
        f"- suite: `{summary['suite']}`",
        f"- defense: `{summary['defense']}`",
        f"- mode: `{summary['mode']}`",
        f"- sanitize_mode: `{summary['sanitize_mode']}`",
        f"- note: {summary['oracle_warning']}",
        "",
        "| Utility Under Attack | Security | Targeted ASR | Runtime sec | ToolGate decisions | Blocked |",
        "|---:|---:|---:|---:|---:|---:|",
        f"| {summary['utility_under_attack']:.3f} | {summary['security']:.3f} | {summary['targeted_asr']:.3f} | {summary['total_runtime_sec']:.2f} | {audit.get('tool_gate_decision_count', 0)} | {audit.get('blocked_tool_calls', 0)} |",
        "",
        "## Firewall Internals",
        "",
        f"- registered_tool_rate: {audit.get('registered_tool_rate', 0.0):.3f}",
        f"- unknown_tool_rate: {audit.get('unknown_tool_rate', 0.0):.3f}",
        f"- policy_p50_ms: {audit.get('policy_p50_ms', 0.0):.3f}",
        f"- policy_p95_ms: {audit.get('policy_p95_ms', 0.0):.3f}",
        f"- rule_hit_counts: {audit.get('rule_hit_counts', {})}",
        "",
    ]
    return "\n".join(lines)


def _normalize_model(model: str) -> str:
    if "/" in model and model.startswith("openai-api/"):
        return model.rsplit("/", 1)[-1]
    return model


def _avg_bool(values: Any) -> float:
    values = list(values)
    return float(sum(1 for item in values if item) / len(values)) if values else 0.0


def _mode_warning(mode: str) -> str:
    if mode == "fair":
        return "Fair mode: no injection task GOAL/PROMPT/ground_truth is passed to the firewall."
    if mode == "oracle_user":
        return "Oracle-user mode: user-task oracle hints may be used for authorization; not a primary result."
    return "Oracle-full mode: attack goal signatures may be used; upper-bound diagnostic only."


if __name__ == "__main__":
    main()




