from __future__ import annotations

from agentbrake.eval.agentdojo.fact_adapter import agentdojo_facts_from_action
from agentbrake.models import ActionIR


def test_agentdojo_facts_sync_untrusted_source_and_contract_match():
    action = ActionIR(
        action_id="act1",
        raw_action="AgentDojo send_money({'amount': '100'})",
        tool="AgentDojo",
        cwd=".",
        semantic_action="financial_transaction",
        risk="critical",
        risk_tags=["agentdojo"],
        affected_assets=["agentdojo:send_money"],
        requires=[],
        metadata={
            "agentdojo": {
                "suite": "banking",
                "tool_name": "send_money",
                "tool_category": "financial_commit",
                "semantic_action": "financial_transaction",
                "risk": "critical",
                "side_effect": True,
                "source_has_untrusted": True,
                "untrusted_observation_seen": True,
                "task_authorized_tool": False,
                "unknown_tool": False,
                "tool_args": {"amount": "100", "recipient": "attacker"},
                "contract_match": "violation",
                "violation_reason": ["not_required_by_user_goal"],
            }
        },
    )

    facts = agentdojo_facts_from_action(action)
    values = {(fact.namespace, fact.key): fact.value for fact in facts}

    assert values[("source", "has_untrusted")] is True
    assert values[("source", "trust_floor")] == "untrusted"
    assert values[("contract", "match")] == "violation"


def test_agentdojo_facts_emit_message_send_and_private_data_flags():
    action = ActionIR(
        action_id="act2",
        raw_action="AgentDojo send_direct_message({'body': 'hi'})",
        tool="AgentDojo",
        cwd=".",
        semantic_action="send_external_message",
        risk="high",
        risk_tags=["agentdojo"],
        affected_assets=["agentdojo:send_direct_message"],
        requires=[],
        metadata={
            "agentdojo": {
                "suite": "slack",
                "tool_name": "send_direct_message",
                "tool_category": "external_message_send",
                "semantic_action": "send_external_message",
                "risk": "high",
                "side_effect": True,
                "private_data_seen": True,
                "task_authorized_tool": False,
                "unknown_tool": False,
                "tool_args": {"body": "hi"},
            }
        },
    )

    facts = agentdojo_facts_from_action(action)
    values = {(fact.namespace, fact.key): fact.value for fact in facts}

    assert values[("agentdojo", "external_message_send")] is True
    assert values[("agentdojo", "private_data_seen")] is True
    assert values[("agentdojo", "task_authorized_tool")] is False


