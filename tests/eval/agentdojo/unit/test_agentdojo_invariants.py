from __future__ import annotations

from agentbrake.policy_engine.facts import PolicyFact, PolicyFactSet
from agentbrake.policy_engine.invariants import InvariantEngine


def test_agentdojo_financial_message_private_data_and_booking_invariants_fire():
    facts = PolicyFactSet(
        [
            PolicyFact.of("agentdojo", "suite", "banking", evidence_refs=["a1"]),
            PolicyFact.of("agentdojo", "tool_call_boundary", True, evidence_refs=["a1"]),
            PolicyFact.of("source", "has_untrusted", True, evidence_refs=["src1"]),
            PolicyFact.of("agentdojo", "financial_commit", True, evidence_refs=["a1"]),
            PolicyFact.of("agentdojo", "message_send", True, evidence_refs=["a1"]),
            PolicyFact.of("agentdojo", "private_data_read", True, evidence_refs=["a1"]),
            PolicyFact.of("history", "private_data_seen", True, evidence_refs=["h1"]),
            PolicyFact.of("agentdojo", "booking_commit", True, evidence_refs=["a1"]),
            PolicyFact.of("agentdojo", "task_authorized_tool", False, evidence_refs=["a1"]),
            PolicyFact.of("agentdojo", "external_share", True, evidence_refs=["a1"]),
            PolicyFact.of("agentdojo", "workspace_acl_mutation", True, evidence_refs=["a1"]),
            PolicyFact.of("agentdojo", "credential_change", True, evidence_refs=["a1"]),
            PolicyFact.of("agentdojo", "destructive_update", True, evidence_refs=["a1"]),
            PolicyFact.of("agentdojo", "tool_name", "send_money", evidence_refs=["a1"]),
            PolicyFact.of("agentdojo", "tool_category", "unknown_side_effect", evidence_refs=["a1"]),
        ]
    )

    hits = InvariantEngine().evaluate(facts)
    rule_ids = {hit.rule_id for hit in hits}

    assert "ADJ-FIN-001" in rule_ids
    assert "ADJ-MSG-001" in rule_ids
    assert "ADJ-PRIVATE-EGRESS-001" in rule_ids
    assert "ADJ-BOOK-001" in rule_ids
    assert "ADJ-TRAVEL-001" in rule_ids
    assert "ADJ-ACL-001" in rule_ids
    assert "ADJ-CRED-001" in rule_ids
    assert "ADJ-WORKSPACE-001" in rule_ids
    assert "ADJ-WORKSPACE-002" in rule_ids
    assert "ADJ-UNKNOWN-001" in rule_ids


