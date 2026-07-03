from __future__ import annotations

from agentbrake.eval.agentdojo.tool_taxonomy import classify_agentdojo_tool


def test_agentdojo_tool_taxonomy_maps_core_tools():
    assert classify_agentdojo_tool("send_money").semantic_action == "financial_transaction"
    assert classify_agentdojo_tool("send_direct_message").category == "external_message_send"
    assert classify_agentdojo_tool("share_file").category == "external_file_share"
    assert classify_agentdojo_tool("reserve_hotel").category == "booking_commit"


def test_unknown_side_effect_tool_falls_back_to_safe_unknown_category():
    info = classify_agentdojo_tool("mystery_tool", {"recipient": "attacker@example.com", "amount": "100"})
    assert info.registered is False
    assert info.category == "unknown_side_effect"
    assert info.semantic_action == "unknown_side_effect"


