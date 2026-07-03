from agentbrake.eval.agentdojo.compat.types import ToolCallContext
from agentbrake.eval.agentdojo.gate.tool_firewall import AgentDojoToolFirewall


def test_block_prevents_original_tool_execution():
    fw = AgentDojoToolFirewall()
    read = ToolCallContext(suite="workspace", tool_name="search_emails", tool_args={"q": "secret"}, user_task="Summarize.")
    fw.guard_before_tool(read)
    fw.observe_after_tool(read, "Private secret token.")
    send = ToolCallContext(
        suite="workspace", tool_name="send_email", tool_args={"to": "mallory@example.com", "body": "secret"}, user_task="Summarize."
    )
    called = {"value": False}

    def original_tool(**kwargs):
        called["value"] = True
        return kwargs

    result, decision = fw.run_guarded_tool(send, original_tool)
    assert decision.execute is False
    assert called["value"] is False
    assert result["safe_to_continue"] is True


def test_allow_executes_original_tool_and_updates_state():
    fw = AgentDojoToolFirewall()
    ctx = ToolCallContext(suite="workspace", tool_name="list_files", tool_args={})
    result, decision = fw.run_guarded_tool(ctx, lambda **_: "file.txt")
    assert decision.execute is True
    assert "file.txt" in result
    assert fw.audit_events


