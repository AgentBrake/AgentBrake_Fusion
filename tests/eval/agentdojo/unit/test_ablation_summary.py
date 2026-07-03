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


def row(variant: str, idx: int, *, injection: bool, user: bool, blocked: bool = False, repeated: int = 0, reason: str = "attack_active"):
    return {
        "suite": "banking",
        "variant": variant,
        "method": variant,
        "user_task_id": f"user_task_{idx}",
        "injection_task_id": "injection_task_1",
        "raw_agentdojo_injection_task_success": injection,
        "raw_agentdojo_user_task_success": user,
        "blocked_case": blocked,
        "confirmation_case": False,
        "confirmation_required_count": 0,
        "confirmation_executed_count": 0,
        "repeated_block_count": repeated,
        "selection_reason": reason,
        "policy_latency_p50_ms": 1.0,
        "full_trace_missing": False,
    }


def test_ablation_summary_metrics_and_flags() -> None:
    module = load_module()
    rows = [
        row("full", 1, injection=False, user=True, blocked=True),
        row("full", 2, injection=False, user=True, reason="safe_side_effect_control"),
        row("rule_only", 1, injection=False, user=False, blocked=True),
        row("rule_only", 2, injection=False, user=False, reason="safe_side_effect_control"),
        row("no_binding", 1, injection=False, user=True, blocked=True),
        row("no_binding", 2, injection=False, user=False, blocked=True, reason="safe_side_effect_control"),
        row("legacy_no_context_graph", 1, injection=True, user=True, blocked=False),
        row("legacy_no_context_graph", 2, injection=False, user=True, reason="safe_side_effect_control"),
        row("no_recovery_guidance", 1, injection=False, user=False, blocked=True, repeated=1),
        row("no_recovery_guidance", 2, injection=False, user=True, reason="safe_side_effect_control"),
    ]
    summary = module.build_legacy_summary(rows, 2)
    assert list(summary["main_table"]) == list(module.LEGACY_VARIANTS)
    assert summary["main_table"]["full"]["targeted_asr"] == 0.0
    assert summary["attack_active_subset_metrics"]["legacy_no_context_graph"]["attack_suppression_rate"] == 0.0
    assert summary["main_table"]["full"]["post_block_user_success_rate"] == 1.0
    assert summary["interpretation_flags"]["rule_only"]["contribution_established"]
    assert summary["interpretation_flags"]["legacy_no_context_graph"]["contribution_established"]
