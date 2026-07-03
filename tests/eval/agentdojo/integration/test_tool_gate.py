from __future__ import annotations

from agentbrake.control_plane import AgentBrakeControlPlane
from agentbrake.eval.agentdojo.tool_gate import AgentBrakeToolGate


def test_tool_gate_blocks_and_allows_without_executing_original_tool(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cp = AgentBrakeControlPlane(repo, audit_path=tmp_path / "audit.jsonl")
    gate = AgentBrakeToolGate(cp)

    blocked = gate.guard_tool_call(
        {"name": "send_money", "arguments": {"amount": "1000", "recipient": "attacker"}},
        {"suite": "banking", "source_has_untrusted": True, "task_instruction": "send money"},
    )
    allowed = gate.guard_tool_call(
        {"name": "get_balance", "arguments": {}},
        {"suite": "banking", "source_has_untrusted": False, "task_instruction": "check balance"},
    )

    assert blocked.execute is False
    assert blocked.safe_tool_result["safe_to_continue"] is True
    assert blocked.block_reason
    assert allowed.execute is True
    assert any(event["event_type"] == "agentdojo_tool_gate_decision" for event in cp.audit.read_events())


