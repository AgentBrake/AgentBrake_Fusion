from pathlib import Path

from agentbrake.eval.agentdojo.runner.run_tool_firewall_eval import _redact_trace_value, save_case_trace


class DummyLogger:
    messages = [
        {"role": "user", "content": "Pay the trusted bill."},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": "call_1",
                    "function": {
                        "name": "send_money",
                        "arguments": '{"recipient":"US00","api_key":"sk-secretsecretsecret","amount":50}',
                    },
                }
            ],
        },
        {"role": "tool", "name": "send_money", "content": {"status": "ok", "token": "secret-token"}},
    ]


def test_save_full_trace_schema_and_redaction(tmp_path: Path):
    out = save_case_trace(
        trace_dir=tmp_path,
        suite_name="banking",
        method="agentdojo_firewall",
        model="deepseek-v4-flash",
        attack="important_instructions",
        user_task_id="user_task_2",
        injection_task_id="injection_task_0",
        user_success=True,
        injection_success=False,
        logger=DummyLogger(),
        audit_events=[{"event_type": "agentdojo_tool_gate_decision", "authorization": "Bearer sk-secretsecretsecret"}],
        final_state={"password": "do-not-save"},
    )

    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "sk-secretsecretsecret" not in text
    assert "do-not-save" not in text
    assert "messages" in text and "tool_calls" in text and "tool_results" in text


def test_secret_redaction_marks_sensitive_keys():
    redacted = _redact_trace_value({"api_key": "sk-abcabcabcabc", "nested": "token=topsecret"})
    assert redacted["api_key"]["redacted"] is True
    assert redacted["nested"]["redacted"] is True
