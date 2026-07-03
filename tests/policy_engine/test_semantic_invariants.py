from agentbrake.policy_engine.facts import PolicyFact, PolicyFactSet
from agentbrake.policy_engine.invariants import InvariantEngine


def test_semantic_invariant_registry_keeps_legacy_ids():
    facts = PolicyFactSet(
        [
            PolicyFact.of("asset", "touched_type", "secret_file", evidence_refs=["asset1"]),
            PolicyFact.of("contract", "forbidden_file_touch", True, evidence_refs=["asset1"]),
        ]
    )

    hits = InvariantEngine().evaluate(facts)

    assert hits[0].rule_id == "INV-SECRET-001"
    assert hits[0].constraints["execution_env"] == "none"


def test_confirmed_history_secret_taint_with_network_is_secret_egress():
    facts = PolicyFactSet(
        [
            PolicyFact.of("history", "secret_taint", True, evidence_refs=["state1"]),
            PolicyFact.of("history", "confirmed_secret_taint", True, evidence_refs=["state1"]),
            PolicyFact.of("action", "network_capability", True, evidence_refs=["act1"]),
        ]
    )

    hits = InvariantEngine().evaluate(facts)

    assert {hit.rule_id for hit in hits} == {"INV-EGRESS-001"}


def test_attempted_history_secret_taint_with_network_is_governed_not_confirmed_egress():
    facts = PolicyFactSet(
        [
            PolicyFact.of("history", "secret_taint", True, evidence_refs=["state1"]),
            PolicyFact.of("history", "attempted_secret_taint", True, evidence_refs=["state1"]),
            PolicyFact.of("action", "network_capability", True, evidence_refs=["act1"]),
        ]
    )

    hits = InvariantEngine().evaluate(facts)

    assert {hit.rule_id for hit in hits} == {"INV-EGRESS-001B"}


def test_agentdojo_invariants_fire_for_untrusted_sensitive_message():
    facts = PolicyFactSet(
        [
            PolicyFact.of("agentdojo", "suite", "slack", evidence_refs=["act1"]),
            PolicyFact.of("agentdojo", "message_send", True, evidence_refs=["act1"]),
            PolicyFact.of("agentdojo", "tool_args_sensitive", True, evidence_refs=["act1"]),
            PolicyFact.of("agentdojo", "state_mutation", True, evidence_refs=["act1"]),
            PolicyFact.of("source", "has_untrusted", True, evidence_refs=["src1"]),
            PolicyFact.of("agentdojo", "tool_call_boundary", True, evidence_refs=["act1"]),
        ]
    )

    hits = InvariantEngine().evaluate(facts)

    assert {hit.rule_id for hit in hits} >= {"ADJ-MSG-001", "ADJ-WORKSPACE-DEL-001"}
