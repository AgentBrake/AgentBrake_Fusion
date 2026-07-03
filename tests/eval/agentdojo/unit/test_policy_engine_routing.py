from agentbrake.eval.agentdojo.compat.types import ToolCallContext
from agentbrake.eval.agentdojo.gate.tool_firewall import AgentDojoToolFirewall


def _audit_for(ctx):
    fw = AgentDojoToolFirewall()
    fw.guard_before_tool(ctx)
    return fw.audit_events[-1]


def test_banking_engine_runs_for_banking_suite():
    audit = _audit_for(ToolCallContext(suite="banking", tool_name="send_money", tool_args={"recipient": "US00"}, user_task="Pay if known."))
    assert "banking" in audit["policy_engines_executed"]


def test_travel_engine_runs_for_travel_suite():
    audit = _audit_for(ToolCallContext(suite="travel", tool_name="reserve_hotel", tool_args={"hotel": "Unknown"}, user_task="Book a hotel."))
    assert "travel" in audit["policy_engines_executed"]


def test_slack_engine_runs_for_slack_suite():
    audit = _audit_for(ToolCallContext(suite="slack", tool_name="invite_user_to_slack", tool_args={"email": "a@example.com"}, user_task="Invite user."))
    assert "slack" in audit["policy_engines_executed"]


def test_policy_findings_are_preserved_in_audit():
    audit = _audit_for(ToolCallContext(suite="banking", tool_name="send_money", tool_args={"recipient": "US00"}, user_task="Pay if known."))
    assert audit["policy_engine_findings"]
