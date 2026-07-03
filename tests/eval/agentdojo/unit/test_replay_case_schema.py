import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "16_validate_replay_cases.py"
spec = importlib.util.spec_from_file_location("validate_replay_cases_script", SCRIPT)
assert spec and spec.loader
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def test_canonical_case_requires_posix_paths_and_safe_success_flags():
    case = {
        "case_schema_version": "agentdojo_replay_case_v1",
        "case_id": "c1",
        "source": "agentdojo_trace",
        "source_trace": "a/b.json",
        "source_trace_file": "a/b.json",
        "source_raw_file": "raw/r.json",
        "suite": "banking",
        "method": "none",
        "model": "deepseek-v4-flash",
        "attack": "important_instructions",
        "user_task_id": "user_task_0",
        "injection_task_id": "injection_task_0",
        "label": "safe",
        "prior": [],
        "prior_messages": [],
        "prior_tool_results": [],
        "current_tool_call": {"tool": "send_money", "args": {}},
        "tool_call": {"tool": "send_money", "args": {}},
        "expected_decision": "allow",
        "ground_truth_violation": {"type": "benign_user_requested_payment", "unsafe_args": [], "evidence": {}},
        "expected_reason_codes": [],
        "label_source": "agentdojo_successful_benign_trace",
        "review_status": "auto_labeled_pending_review",
        "case_origin": "trace_extracted",
        "standard_agentdojo_e2e_score": False,
        "expected_agentdojo_user_success": True,
        "expected_agentdojo_injection_success": False,
    }
    assert validator.validate_case(case, Path("case.json")) == []


def test_unsafe_read_only_tool_is_invalid():
    case = {
        field: "x"
        for field in validator.DERIVED_REQUIRED
        if field not in {"standard_agentdojo_e2e_score", "current_tool_call", "tool_call", "ground_truth_violation", "expected_reason_codes", "prior", "prior_messages", "prior_tool_results", "expected_agentdojo_user_success", "expected_agentdojo_injection_success"}
    }
    case.update(
        {
            "standard_agentdojo_e2e_score": False,
            "label": "unsafe",
            "expected_decision": "block",
            "current_tool_call": {"tool": "get_webpage", "args": {}},
            "tool_call": {"tool": "get_webpage", "args": {}},
            "ground_truth_violation": {"type": "private_data_exfiltration", "unsafe_args": [], "evidence": {}},
            "expected_reason_codes": [],
            "prior": [],
            "prior_messages": [],
            "prior_tool_results": [],
            "expected_agentdojo_user_success": False,
            "expected_agentdojo_injection_success": True,
        }
    )
    assert any("read-only" in error for error in validator.validate_case(case, Path("case.json")))
