from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path("experiments/agentdojo/scripts/33_summarize_ablation_diagnostic.py")


def load_module():
    spec = importlib.util.spec_from_file_location("summarize_ablation", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def row(variant: str, idx: int, *, blocked: bool, user: bool, injection: bool, bucket: str = "provenance_conflict"):
    return {
        "suite": "banking",
        "variant": variant,
        "method": variant,
        "user_task_id": f"u{idx}",
        "injection_task_id": f"i{idx}",
        "raw_agentdojo_injection_task_success": injection,
        "raw_agentdojo_user_task_success": user,
        "blocked_case": blocked,
        "confirmation_case": False,
        "repeated_block_count": 0,
        "selection_reason": "attack_active",
        "actiongraph_bucket": bucket,
        "policy_latency_p50_ms": 1.0,
        "full_trace_missing": False,
        "reason_codes": ["AG-PROVENANCE-CONFLICT"],
    }


def test_actiongraph_summary_excludes_legacy_no_context_graph() -> None:
    module = load_module()
    rows = [
        row("full", 1, blocked=True, user=True, injection=False),
        row("flatten_action_graph", 1, blocked=False, user=True, injection=True),
        row("no_actiongraph_provenance_edges", 1, blocked=False, user=True, injection=True),
        row("no_actiongraph_dataflow_edges", 1, blocked=True, user=True, injection=False, bucket="dataflow_exfiltration"),
        row("no_actiongraph_history_edges", 1, blocked=True, user=True, injection=False, bucket="history_recovery"),
    ]
    summary = module.build_actiongraph_summary(rows, 1)
    assert list(summary["main_table"]) == list(module.ACTIONGRAPH_VARIANTS)
    assert "no_context_graph" not in summary["main_table"]
    assert "legacy_no_context_graph" not in summary["main_table"]
    assert summary["pairwise_delta"]["by_variant"]["flatten_action_graph"]["full_block_ablation_allow"] == 1
    assert "not clearly separated" in module.render_actiongraph_md(summary) or "contribution" in module.render_actiongraph_md(summary)
