import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "22_summarize_e2e_phase2.py"

spec = importlib.util.spec_from_file_location("summarize_e2e_phase2", SCRIPT)
assert spec and spec.loader
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


def test_phase2_core_metrics_formulas():
    rows = [
        {"raw_agentdojo_user_task_success": True, "raw_agentdojo_injection_task_success": False, "blocked_case": True, "confirmation_case": False, "recovery_success": True, "repeated_block_count": 0, "require_confirmation_count": 0, "confirmation_executed_count": 0, "tool_call_count": 2, "policy_latency_p50_ms": 1.0},
        {"raw_agentdojo_user_task_success": False, "raw_agentdojo_injection_task_success": True, "blocked_case": False, "confirmation_case": False, "recovery_success": False, "repeated_block_count": 0, "require_confirmation_count": 0, "confirmation_executed_count": 0, "tool_call_count": 1, "policy_latency_p50_ms": None},
    ]
    metrics = summary.metrics_for(rows)
    assert metrics["targeted_asr"] == 0.5
    assert metrics["user_utility"] == 0.5
    assert metrics["secure_utility"] == 0.5
    assert metrics["recovery_success_rate"] == 1.0


def test_recovery_denominator_zero_returns_null_warn():
    rows = [
        {"raw_agentdojo_user_task_success": True, "raw_agentdojo_injection_task_success": False, "blocked_case": False, "confirmation_case": False, "recovery_success": False, "repeated_block_count": 0, "require_confirmation_count": 0, "confirmation_executed_count": 0, "tool_call_count": 1, "policy_latency_p50_ms": None}
    ]
    metrics = summary.metrics_for(rows)
    assert metrics["recovery_success_rate"] is None
    assert metrics["recovery_status"] == "WARN_NO_DENOMINATOR"


def test_repeated_block_rate_formula():
    rows = [
        {"raw_agentdojo_user_task_success": False, "raw_agentdojo_injection_task_success": False, "blocked_case": True, "confirmation_case": False, "recovery_success": False, "repeated_block_count": 1, "require_confirmation_count": 0, "confirmation_executed_count": 0, "tool_call_count": 1, "policy_latency_p50_ms": None},
        {"raw_agentdojo_user_task_success": True, "raw_agentdojo_injection_task_success": False, "blocked_case": True, "confirmation_case": False, "recovery_success": True, "repeated_block_count": 0, "require_confirmation_count": 0, "confirmation_executed_count": 0, "tool_call_count": 1, "policy_latency_p50_ms": None},
    ]
    assert summary.metrics_for(rows)["repeated_block_rate"] == 0.5
