"""Convert AgentDojo metadata into PolicyGraph facts."""

from __future__ import annotations

from typing import Any

from ...models import ActionIR
from ...policy_engine.facts import PolicyFact


def agentdojo_facts_from_action(action: ActionIR) -> list[PolicyFact]:
    metadata = action.metadata.get("agentdojo")
    if not isinstance(metadata, dict):
        return []
    refs = [action.action_id]
    category = str(metadata.get("tool_category") or "")
    semantic = str(metadata.get("semantic_action") or action.semantic_action)
    risk = str(metadata.get("risk") or action.risk)
    side_effect = bool(metadata.get("side_effect", action.side_effect))
    read_private_data = bool(metadata.get("read_private_data") or category == "private_data_read" or semantic.startswith("read_"))
    external_message_send = bool(
        metadata.get("external_message_send") or category == "external_message_send" or semantic == "send_external_message"
    )
    financial_commit = bool(metadata.get("financial_commit") or category == "financial_commit" or semantic == "financial_transaction")
    booking_commit = bool(metadata.get("booking_commit") or category == "booking_commit" or semantic == "booking_commit")
    workspace_mutation = bool(
        metadata.get("workspace_mutation")
        or category in {"workspace_mutation", "file_mutation", "destructive_update", "privilege_or_membership_change"}
    )
    destructive_update = bool(
        metadata.get("destructive_update")
        or category in {"destructive_update", "destructive_file_operation", "destructive_membership_update"}
    )
    credential_change = bool(metadata.get("credential_change") or category in {"account_security_change", "credential_change"})
    source_has_untrusted = bool(metadata.get("source_has_untrusted") or metadata.get("untrusted_observation_seen"))
    trust_floor = "untrusted" if source_has_untrusted else metadata.get("trust_floor", "trusted")
    contract_match = (
        "violation" if not bool(metadata.get("task_authorized_tool")) and side_effect else metadata.get("contract_match", "unknown")
    )
    facts = [
        PolicyFact.of("agentdojo", "suite", metadata.get("suite"), evidence_refs=refs),
        PolicyFact.of("agentdojo", "tool_name", metadata.get("tool_name"), evidence_refs=refs),
        PolicyFact.of("agentdojo", "tool_category", category, evidence_refs=refs),
        PolicyFact.of("agentdojo", "semantic_action", semantic, evidence_refs=refs),
        PolicyFact.of("agentdojo", "risk", risk, evidence_refs=refs),
        PolicyFact.of("agentdojo", "side_effect", side_effect, evidence_refs=refs),
        PolicyFact.of("agentdojo", "user_task_id", metadata.get("user_task_id"), evidence_refs=refs),
        PolicyFact.of("agentdojo", "injection_task_id", metadata.get("injection_task_id"), evidence_refs=refs),
        PolicyFact.of("agentdojo", "attack_surface", metadata.get("attack_surface"), evidence_refs=refs),
        PolicyFact.of("agentdojo", "allowed_tool_categories", metadata.get("allowed_tool_categories", []), evidence_refs=refs),
        PolicyFact.of("agentdojo", "forbidden_attack_goals", metadata.get("forbidden_attack_goals", []), evidence_refs=refs),
        PolicyFact.of("agentdojo", "tool_call_boundary", True, evidence_refs=refs),
        PolicyFact.of("agentdojo", "tool_registered", bool(metadata.get("registered", True)), evidence_refs=refs),
        PolicyFact.of("agentdojo", "source_origin", metadata.get("source_origin", "agentdojo_tool_output"), evidence_refs=refs),
        PolicyFact.of("agentdojo", "read_private_data", read_private_data, evidence_refs=refs),
        PolicyFact.of("agentdojo", "read_private_file", bool(metadata.get("read_private_file")), evidence_refs=refs),
        PolicyFact.of("agentdojo", "read_private_messages", bool(metadata.get("read_private_messages")), evidence_refs=refs),
        PolicyFact.of("agentdojo", "read_private_user_info", bool(metadata.get("read_private_user_info")), evidence_refs=refs),
        PolicyFact.of("agentdojo", "read_public_travel_data", bool(metadata.get("read_public_travel_data")), evidence_refs=refs),
        PolicyFact.of("agentdojo", "read_untrusted_data", bool(metadata.get("read_untrusted_data")), evidence_refs=refs),
        PolicyFact.of("agentdojo", "external_message_send", external_message_send, evidence_refs=refs),
        PolicyFact.of("agentdojo", "message_send", external_message_send or category == "message_send", evidence_refs=refs),
        PolicyFact.of("agentdojo", "external_commit", external_message_send or bool(metadata.get("external_commit")), evidence_refs=refs),
        PolicyFact.of("agentdojo", "financial_commit", financial_commit, evidence_refs=refs),
        PolicyFact.of("agentdojo", "booking_commit", booking_commit, evidence_refs=refs),
        PolicyFact.of("agentdojo", "workspace_mutation", workspace_mutation, evidence_refs=refs),
        PolicyFact.of("agentdojo", "destructive_update", destructive_update, evidence_refs=refs),
        PolicyFact.of("agentdojo", "credential_change", credential_change, evidence_refs=refs),
        PolicyFact.of("agentdojo", "external_share", bool(metadata.get("external_share")), evidence_refs=refs),
        PolicyFact.of("agentdojo", "workspace_acl_mutation", bool(metadata.get("workspace_acl_mutation")), evidence_refs=refs),
        PolicyFact.of("agentdojo", "state_mutation", side_effect, evidence_refs=refs),
        PolicyFact.of(
            "agentdojo",
            "untrusted_observation_seen",
            source_has_untrusted or bool(metadata.get("untrusted_observation_seen")),
            evidence_refs=refs,
        ),
        PolicyFact.of("agentdojo", "private_data_seen", bool(metadata.get("private_data_seen")), evidence_refs=refs),
        PolicyFact.of("agentdojo", "financial_data_seen", bool(metadata.get("financial_data_seen")), evidence_refs=refs),
        PolicyFact.of("agentdojo", "task_authorized_tool", bool(metadata.get("task_authorized_tool")), evidence_refs=refs),
        PolicyFact.of("agentdojo", "attack_goal_overlap", bool(metadata.get("attack_goal_overlap")), evidence_refs=refs),
        PolicyFact.of(
            "agentdojo",
            "unknown_tool",
            bool(metadata.get("unknown_tool")) or not bool(metadata.get("registered", True)),
            evidence_refs=refs,
        ),
        PolicyFact.of("agentdojo", "tool_args_sensitive", _tool_args_sensitive(metadata.get("tool_args")), evidence_refs=refs),
        PolicyFact.of("source", "has_untrusted", source_has_untrusted, evidence_refs=refs),
        PolicyFact.of("source", "trust_floor", trust_floor, evidence_refs=refs),
        PolicyFact.of("contract", "match", metadata.get("contract_match", contract_match), evidence_refs=refs),
        PolicyFact.of("contract", "violation_reason", metadata.get("violation_reason", []), evidence_refs=refs),
        PolicyFact.of("history", "private_data_seen", bool(metadata.get("private_data_seen")), evidence_refs=refs),
        PolicyFact.of("history", "financial_data_seen", bool(metadata.get("financial_data_seen")), evidence_refs=refs),
    ]
    return facts


def _tool_args_sensitive(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    sensitive_keys = {"password", "token", "secret", "ssn", "account", "routing", "card", "email", "recipient", "message", "body"}
    text = " ".join(f"{k}={v}" for k, v in value.items()).lower()
    return any(key in text for key in sensitive_keys)

