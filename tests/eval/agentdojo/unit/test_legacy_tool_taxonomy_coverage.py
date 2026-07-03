from __future__ import annotations

from agentbrake.eval.agentdojo.tool_gate import taxonomy_coverage_summary
from agentbrake.eval.agentdojo.tool_taxonomy import load_agentdojo_taxonomy


def test_agentdojo_taxonomy_covers_official_tool_subset():
    tools = [
        "get_balance",
        "send_money",
        "get_unread_emails",
        "send_email",
        "get_channels",
        "send_direct_message",
        "get_user_information",
        "reserve_hotel",
        "run_bash_command",
    ]
    report = taxonomy_coverage_summary(tools)
    assert report["registered_tool_rate"] == 1.0
    assert all(tool in load_agentdojo_taxonomy() for tool in tools)


