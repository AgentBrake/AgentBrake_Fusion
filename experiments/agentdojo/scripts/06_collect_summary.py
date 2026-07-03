from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
REPORT_DIR = ROOT / "experiments" / "agentdojo" / "reports"
LOG_DIR = ROOT / "experiments" / "agentdojo" / "logs"


def main() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    runs = load_run_reports()
    coverage = load_json(REPORT_DIR / "tool_coverage.json") or {}
    summary = {
        "runs": runs,
        "tool_coverage": coverage,
        "fairness": {
            "fair_mode": "Fair mode does not use injection ground truth.",
            "oracle_mode": "Oracle mode is an upper bound only.",
            "iterator": "The failure-sample iterator only generates candidate rules and does not merge them automatically.",
        },
    }
    (REPORT_DIR / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    (REPORT_DIR / "summary.md").write_text(render_summary(runs, coverage), encoding="utf-8")
    print(REPORT_DIR / "summary.md")


def load_run_reports() -> list[dict[str, Any]]:
    paths = list((REPORT_DIR / "runs").glob("*.json")) if (REPORT_DIR / "runs").exists() else []
    paths += list(LOG_DIR.glob("**/reports/*.json")) if LOG_DIR.exists() else []
    out: list[dict[str, Any]] = []
    for path in sorted(set(paths)):
        data = load_json(path)
        if isinstance(data, dict) and {"utility_under_attack", "security"} & set(data):
            data["_path"] = str(path)
            out.append(data)
    return out


def render_summary(runs: list[dict[str, Any]], coverage: dict[str, Any]) -> str:
    lines = ["# AgentDojo Firewall Summary", ""]
    lines.extend(render_main_results(runs))
    lines.extend(render_tool_coverage(coverage))
    lines.extend(render_decision_distribution(runs))
    lines.extend(render_rule_hits(runs))
    lines.extend(render_performance(runs))
    lines.extend(
        [
            "## Fairness Statement",
            "",
            "Fair mode does not use injection ground truth, InjectionTask.GOAL, InjectionTask.PROMPT, or final scoring state.",
            "",
            "Oracle mode is only an upper bound and must not be reported as the primary defense result.",
            "",
            "The failure-sample iterator only generates candidate rules. It does not automatically modify or merge core firewall rules.",
            "",
        ]
    )
    return "\n".join(lines)


def render_main_results(runs: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Table 1: AgentDojo Main Results",
        "",
        "| Method | User Utility | Targeted ASR | Security Rate | Secure Utility | Total Time | Notes |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    labels = {
        "none": "No Defense",
        "tool_filter": "Tool Filter",
        "gateway_only": "Gateway-only Fast",
        "agentbrake_toolgate": "Gateway-only Fast",
        "agentdojo_firewall": "AgentDojo Firewall Fair",
    }
    rows = runs or []
    if not rows:
        rows = [
            {"defense": key, "user_utility": 0, "security_rate": 0, "secure_utility": 0, "targeted_asr": 0, "total_runtime_min": 0, "mode": ""}
            for key in ["none", "tool_filter", "gateway_only", "agentdojo_firewall"]
        ]
        rows.append(
            {
                "defense": "agentdojo_firewall",
                "user_utility": 0,
                "security_rate": 0,
                "secure_utility": 0,
                "targeted_asr": 0,
                "total_runtime_min": 0,
                "mode": "oracle_full",
            }
        )
    for run in rows:
        metrics = normalized_metrics_for_run(run)
        defense = str(run.get("defense", "unknown"))
        mode = str(run.get("mode", ""))
        label = "AgentDojo Firewall Oracle Upper Bound" if mode == "oracle_full" else labels.get(defense, defense)
        lines.append(
            f"| {label} | {metrics['user_utility']:.3f} | {metrics['targeted_asr']:.3f} | {metrics['security_rate']:.3f} | {metrics['secure_utility']:.3f} | {float(run.get('total_runtime_min', 0.0)):.2f} | suite={run.get('suite', '')} mode={mode or 'n/a'} |"
        )
    lines.append("")
    return lines


def normalized_metrics_for_run(run: dict[str, Any]) -> dict[str, float]:
    if "user_utility" in run or "utility_under_attack" in run:
        user_utility = float(run.get("user_utility", run.get("utility_under_attack", 0.0)) or 0.0)
    else:
        user_utility = _avg_bool((run.get("utility_results") or {}).values())
    if "targeted_asr" in run:
        targeted_asr = float(run.get("targeted_asr", 0.0) or 0.0)
    else:
        security_results = list((run.get("security_results") or {}).values())
        targeted_asr = _avg_bool(security_results)
    security_rate = float(run.get("security_rate", 1.0 - targeted_asr) or 0.0)
    if "secure_utility" in run:
        secure_utility = float(run.get("secure_utility", 0.0) or 0.0)
    else:
        utility_results = run.get("utility_results") or {}
        security_results = run.get("security_results") or {}
        secure_utility = _avg_bool(bool(value) and not bool(security_results.get(key, False)) for key, value in utility_results.items())
    return {
        "user_utility": user_utility,
        "targeted_asr": targeted_asr,
        "security_rate": security_rate,
        "secure_utility": secure_utility,
    }


def _avg_bool(values: Any) -> float:
    rows = list(values)
    return sum(1.0 for value in rows if value) / len(rows) if rows else 0.0


def render_tool_coverage(coverage: dict[str, Any]) -> list[str]:
    lines = [
        "## Table 2: Tool Coverage",
        "",
        "| Suite | Total tools | Registered tools | Unknown tools | Unknown rate |",
        "|---|---:|---:|---:|---:|",
    ]
    for suite, item in sorted((coverage.get("suites") or {}).items()):
        lines.append(
            f"| {suite} | {item.get('official_tool_count', 0)} | {len(item.get('registered_tools', []))} | {len(item.get('unknown_tools', []))} | {float(item.get('unknown_tool_rate', 0.0)):.3f} |"
        )
    lines.append("")
    return lines


def render_decision_distribution(runs: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Table 3: ToolGate Decision Distribution",
        "",
        "| 鏂规硶 | allow | block | safe_blocked_result | unknown_tool | tool_gate_decisions |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for run in runs:
        audit = run.get("agentdojo_firewall_audit_summary") or {}
        decisions = int(audit.get("tool_gate_decision_count", audit.get("total_tool_calls_gated", 0)) or 0)
        block = int(audit.get("blocked_tool_calls", 0) or 0)
        unknown = round(float(audit.get("unknown_tool_rate", 0.0) or 0.0) * decisions)
        lines.append(f"| {run.get('defense', '')} | {decisions - block} | {block} | {block} | {unknown} | {decisions} |")
    lines.append("")
    return lines


def render_rule_hits(runs: list[dict[str, Any]]) -> list[str]:
    hits: Counter[str] = Counter()
    for run in runs:
        hits.update((run.get("agentdojo_firewall_audit_summary") or {}).get("rule_hit_counts") or {})
    lines = [
        "## Table 4: Rule Hits",
        "",
        "| Rule | Hits | Typical suite | Typical tool | Decision |",
        "|---|---:|---|---|---|",
    ]
    for rule, count in sorted(hits.items()):
        lines.append(f"| {rule} | {count} | mixed | mixed | block |")
    lines.append("")
    return lines


def render_performance(runs: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Table 5: Performance",
        "",
        "| 鏂规硶 | runtime_min | avg_sample_sec | policy_p50_ms | policy_p95_ms |",
        "|---|---:|---:|---:|---:|",
    ]
    for run in runs:
        audit = run.get("agentdojo_firewall_audit_summary") or {}
        sample_count = max(1, len(run.get("per_run") or []))
        runtime_sec = float(run.get("total_runtime_sec", 0.0) or 0.0)
        lines.append(
            f"| {run.get('defense', '')} | {float(run.get('total_runtime_min', 0.0)):.2f} | {runtime_sec / sample_count:.2f} | {float(audit.get('policy_p50_ms', 0.0)):.3f} | {float(audit.get('policy_p95_ms', 0.0)):.3f} |"
        )
    lines.append("")
    return lines


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


if __name__ == "__main__":
    main()



