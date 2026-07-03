from agentbrake.eval.agentdojo.compat.types import ToolCallContext
from agentbrake.eval.agentdojo.evidence.contracts import PaymentIntentContract, payment_contract_from_user_task
from agentbrake.eval.agentdojo.evidence.entity_extractor import extract_entities
from agentbrake.eval.agentdojo.gate.tool_firewall import AgentDojoToolFirewall


def test_payment_intent_contract_defaults_match_policy_requirements():
    contract = PaymentIntentContract(user_requested_payment=True, allowed_payment_purpose="pay bill")
    data = contract.as_dict()
    assert "user_task" in data["allowed_recipient_sources"]
    assert "trusted_bill_metadata" in data["allowed_recipient_sources"]
    assert "injection_text" in data["disallowed_recipient_sources"]
    assert data["amount_policy"] == "must_match_trusted_bill_or_user_confirmation"
    assert data["requires_confirmation_if_ambiguous"] is True


def test_payment_contract_is_inferred_from_user_task():
    contract = payment_contract_from_user_task("Please pay this bill.")
    assert contract.user_requested_payment is True
    assert contract.allowed_payment_purpose == "pay bill"


def test_decision_event_contains_unified_evidence_objects():
    fw = AgentDojoToolFirewall()
    decision = fw.guard_before_tool(
        ToolCallContext(
            suite="banking",
            tool_name="send_money",
            tool_args={"recipient": "US00000000000000000000", "amount": 50},
            user_task="Pay the bill if the recipient is known.",
        )
    )
    evidence = decision.evidence
    assert evidence["agentdojo.tool_call_evidence"]["sink_type"] == "financial_commit"
    assert evidence["agentdojo.task_contract_match"]["status"] in {"match", "violation", "requires_confirmation", "unknown"}
    assert evidence["agentdojo.source_influence_graph"]["evidence_refs"] is not None
    assert evidence["agentdojo.payment_intent_contract"]["requires_confirmation_if_ambiguous"] is True


def test_contractions_do_not_break_single_quoted_entity_extraction():
    entities = extract_entities("I'm going to Paris. My friend recommended 'Le Marais Boutique'.")
    assert "le marais boutique" in entities.values_for("hotel")
    assert "m going to paris. my friend recommended" not in entities.values_for("hotel")
