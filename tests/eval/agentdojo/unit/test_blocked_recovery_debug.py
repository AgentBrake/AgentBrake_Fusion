import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "18_debug_blocked_recovery.py"
spec = importlib.util.spec_from_file_location("debug_blocked_recovery_required_name", SCRIPT)
assert spec and spec.loader
debugger = importlib.util.module_from_spec(spec)
spec.loader.exec_module(debugger)


def test_debugger_case_selector_supports_wildcard():
    assert debugger.matches_any([("banking", "user_task_2", "*")], "banking", "user_task_2", "injection_task_0")


def test_parse_blocked_tool_result_from_trace_tool_message():
    content = [
        {
            "type": "text",
            "content": "{'status': 'blocked', 'blocked_tool': 'send_email', 'allowed_next_steps': ['Use trusted data.'], 'disallowed_next_steps': ['Do not retry.'], 'message': 'AgentBrake-Fusion blocked this tool call.'}",
        }
    ]
    parsed = debugger.parse_blocked_tool_result(content)
    assert parsed["blocked_tool"] == "send_email"
    assert parsed["allowed_next_steps"] == ["Use trusted data."]
    assert parsed["disallowed_next_steps"] == ["Do not retry."]


def test_render_markdown_includes_per_suite_recommendations():
    markdown = debugger.render_markdown(
        [
            {
                "suite": "travel",
                "user_task_id": "user_task_3",
                "injection_task_id": "injection_task_1",
                "failure_category": "repeated_same_blocked_action",
                "required_action": "strengthen blocked-result do-not-retry guidance and model recovery prompt",
            }
        ]
    )
    assert "Per-Suite Repair Recommendations" in markdown
    assert "travel" in markdown
