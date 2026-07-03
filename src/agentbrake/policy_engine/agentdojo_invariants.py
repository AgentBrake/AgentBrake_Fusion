"""AgentDojo-specific semantic invariants."""

from __future__ import annotations

from .constraint_lattice import DecisionConstraints
from .facts import PolicyFactSet
from .semantic_invariants import RegisteredInvariant, SemanticInvariantSpec, _bool


def agentdojo_invariants() -> list[RegisteredInvariant]:
    return [
        _inv(
            "ADJ-FIN-001",
            "untrusted_financial_commit",
            lambda f: _agentdojo(f)
            and _either_untrusted(f)
            and _bool(f, "agentdojo", "financial_commit")
            and not _bool(f, "agentdojo", "task_authorized_tool"),
            ["agentdojo.financial_commit", "source.has_untrusted", "agentdojo.task_authorized_tool"],
            DecisionConstraints(execution_env="none", network_scope="deny", audit_scope="full"),
            ["agentdojo_untrusted_financial_commit"],
            ["block"],
            100,
        ),
        _inv(
            "ADJ-FIN-002",
            "authorized_financial_commit_needs_approval",
            lambda f: _agentdojo(f)
            and _bool(f, "agentdojo", "financial_commit")
            and _bool(f, "agentdojo", "task_authorized_tool")
            and _either_untrusted(f),
            ["agentdojo.financial_commit", "agentdojo.task_authorized_tool", "source.has_untrusted"],
            DecisionConstraints(execution_env="sandbox", human_gate="approval_required", audit_scope="full"),
            ["agentdojo_authorized_financial_commit_requires_approval"],
            ["sandbox_preflight", "human_approval"],
            98,
        ),
        _inv(
            "ADJ-MSG-001",
            "untrusted_external_message",
            lambda f: _agentdojo(f)
            and _either_untrusted(f)
            and _bool(f, "agentdojo", "message_send")
            and not _bool(f, "agentdojo", "task_authorized_tool"),
            ["agentdojo.message_send", "source.has_untrusted", "agentdojo.task_authorized_tool"],
            DecisionConstraints(execution_env="none", network_scope="deny", data_scope="no_secret", audit_scope="full"),
            ["agentdojo_untrusted_external_message_send"],
            ["block"],
            96,
        ),
        _inv(
            "ADJ-PRIVATE-EGRESS-001",
            "private_data_to_external_sink",
            lambda f: _agentdojo(f)
            and (_bool(f, "history", "private_data_seen") or _bool(f, "agentdojo", "private_data_read"))
            and _any(
                f,
                [
                    ("agentdojo", "message_send"),
                    ("agentdojo", "external_commit"),
                    ("agentdojo", "external_file_share"),
                    ("agentdojo", "external_share"),
                ],
            ),
            ["history.private_data_seen", "agentdojo.private_data_read", "agentdojo.message_send", "agentdojo.external_commit"],
            DecisionConstraints(execution_env="none", network_scope="deny", data_scope="no_secret", audit_scope="full"),
            ["agentdojo_private_data_egress"],
            ["block"],
            98,
        ),
        _inv(
            "ADJ-WEB-001",
            "web_post_after_untrusted_or_private",
            lambda f: _agentdojo(f)
            and (_bool(f, "history", "private_data_seen") or _value_in(f, "agentdojo", "source_origin", {"agentdojo_tool_output"}))
            and _bool(f, "agentdojo", "external_commit")
            and _value_in(f, "agentdojo", "tool_name", {"post_webpage"}),
            ["agentdojo.external_commit", "agentdojo.tool_name", "history.private_data_seen"],
            DecisionConstraints(execution_env="none", network_scope="deny", audit_scope="full"),
            ["agentdojo_web_post_block"],
            ["block"],
            94,
        ),
        _inv(
            "ADJ-WORKSPACE-DEL-001",
            "destructive_update_after_untrusted",
            lambda f: _agentdojo(f) and _either_untrusted(f) and _bool(f, "agentdojo", "state_mutation"),
            ["agentdojo.state_mutation", "source.has_untrusted"],
            DecisionConstraints(execution_env="none", audit_scope="full"),
            ["agentdojo_destructive_update"],
            ["block"],
            95,
        ),
        _inv(
            "ADJ-SHARE-001",
            "share_after_private_data_seen",
            lambda f: _agentdojo(f) and _bool(f, "history", "private_data_seen") and _value_in(f, "agentdojo", "tool_name", {"share_file"}),
            ["history.private_data_seen", "agentdojo.tool_name"],
            DecisionConstraints(execution_env="none", audit_scope="full"),
            ["agentdojo_private_file_share"],
            ["block"],
            94,
        ),
        _inv(
            "ADJ-BOOK-001",
            "untrusted_booking_commit",
            lambda f: _agentdojo(f)
            and _either_untrusted(f)
            and _bool(f, "agentdojo", "booking_commit")
            and not _bool(f, "agentdojo", "task_authorized_tool"),
            ["agentdojo.booking_commit", "source.has_untrusted", "agentdojo.task_authorized_tool"],
            DecisionConstraints(execution_env="sandbox", human_gate="approval_required", audit_scope="full"),
            ["agentdojo_untrusted_booking_commit_requires_approval"],
            ["sandbox_preflight", "human_approval"],
            88,
        ),
        _inv(
            "ADJ-TRAVEL-001",
            "untrusted_booking_commit_exact",
            lambda f: _agentdojo(f)
            and _bool(f, "agentdojo", "booking_commit")
            and not _bool(f, "agentdojo", "task_authorized_tool")
            and _either_untrusted(f),
            ["agentdojo.booking_commit", "source.has_untrusted", "agentdojo.task_authorized_tool"],
            DecisionConstraints(execution_env="none", network_scope="deny", audit_scope="full"),
            ["agentdojo_untrusted_booking_commit_block"],
            ["block"],
            94,
        ),
        _inv(
            "ADJ-TRAVEL-002",
            "authorized_booking_commit_requires_approval",
            lambda f: _agentdojo(f)
            and _bool(f, "agentdojo", "booking_commit")
            and _bool(f, "agentdojo", "task_authorized_tool")
            and _either_untrusted(f),
            ["agentdojo.booking_commit", "source.has_untrusted", "agentdojo.task_authorized_tool"],
            DecisionConstraints(execution_env="sandbox", human_gate="approval_required", audit_scope="full"),
            ["agentdojo_authorized_booking_commit_requires_approval"],
            ["sandbox_preflight", "human_approval"],
            92,
        ),
        _inv(
            "ADJ-ACCOUNT-001",
            "credential_change_after_untrusted",
            lambda f: _agentdojo(f)
            and _either_untrusted(f)
            and _value_in(f, "agentdojo", "tool_name", {"update_password", "update_user_info"}),
            ["agentdojo.tool_name", "source.has_untrusted"],
            DecisionConstraints(execution_env="none", audit_scope="full"),
            ["agentdojo_account_change_block"],
            ["block"],
            97,
        ),
        _inv(
            "ADJ-SLACK-MEM-001",
            "slack_membership_change_after_untrusted",
            lambda f: _agentdojo(f)
            and _either_untrusted(f)
            and _value_in(f, "agentdojo", "tool_name", {"invite_user_to_slack", "add_user_to_channel", "remove_user_from_slack"}),
            ["agentdojo.tool_name", "source.has_untrusted"],
            DecisionConstraints(execution_env="none", audit_scope="full"),
            ["agentdojo_slack_membership_change_block"],
            ["block"],
            95,
        ),
        _inv(
            "ADJ-ACL-001",
            "workspace_acl_mutation_with_untrusted_context",
            lambda f: _agentdojo(f) and _bool(f, "agentdojo", "workspace_acl_mutation") and _either_untrusted(f),
            ["agentdojo.workspace_acl_mutation", "source.has_untrusted"],
            DecisionConstraints(execution_env="none", audit_scope="full"),
            ["agentdojo_workspace_acl_block"],
            ["block"],
            95,
        ),
        _inv(
            "ADJ-CRED-001",
            "credential_change_with_untrusted_context",
            lambda f: _agentdojo(f) and _bool(f, "agentdojo", "credential_change") and _either_untrusted(f),
            ["agentdojo.credential_change", "source.has_untrusted"],
            DecisionConstraints(execution_env="none", audit_scope="full"),
            ["agentdojo_credential_change_block"],
            ["block"],
            97,
        ),
        _inv(
            "ADJ-TERMINAL-001",
            "terminal_after_untrusted",
            lambda f: _agentdojo(f) and _value_in(f, "agentdojo", "tool_name", {"run_bash_command"}) and _either_untrusted(f),
            ["agentdojo.tool_name", "source.has_untrusted"],
            DecisionConstraints(execution_env="sandbox", human_gate="approval_required", audit_scope="full"),
            ["agentdojo_terminal_requires_review"],
            ["sandbox_preflight", "human_approval"],
            90,
        ),
        _inv(
            "ADJ-UNKNOWN-001",
            "unknown_side_effect_tool",
            lambda f: _agentdojo(f) and _value_in(f, "agentdojo", "tool_category", {"unknown_side_effect"}),
            ["agentdojo.tool_category"],
            DecisionConstraints(execution_env="sandbox", human_gate="approval_required", audit_scope="full"),
            ["agentdojo_unknown_side_effect"],
            ["sandbox_preflight", "human_approval"],
            82,
        ),
        _inv(
            "ADJ-WORKSPACE-001",
            "workspace_destructive_update_without_authorization",
            lambda f: _agentdojo(f) and _bool(f, "agentdojo", "destructive_update") and not _bool(f, "agentdojo", "task_authorized_tool"),
            ["agentdojo.destructive_update", "agentdojo.task_authorized_tool"],
            DecisionConstraints(execution_env="none", audit_scope="full"),
            ["agentdojo_workspace_destructive_update_block"],
            ["block"],
            96,
        ),
        _inv(
            "ADJ-WORKSPACE-002",
            "private_data_share_block",
            lambda f: _agentdojo(f)
            and _bool(f, "agentdojo", "external_share")
            and (_bool(f, "history", "private_data_seen") or _bool(f, "agentdojo", "private_data_seen")),
            ["agentdojo.external_share", "history.private_data_seen", "agentdojo.private_data_seen"],
            DecisionConstraints(execution_env="none", audit_scope="full"),
            ["agentdojo_private_data_share_block"],
            ["block"],
            96,
        ),
    ]


def _inv(
    invariant_id: str,
    name: str,
    predicate,
    required_fact_keys: list[str],
    min_constraints: DecisionConstraints,
    reason_codes: list[str],
    required_controls: list[str],
    risk_score: int,
) -> RegisteredInvariant:
    spec = SemanticInvariantSpec(
        invariant_id,
        name,
        "",
        required_fact_keys,
        min_constraints,
        reason_codes,
        required_controls,
        risk_score,
        "agentdojo",
    )
    return RegisteredInvariant(spec, predicate, lambda f: f.find("agentdojo")[:8])


def _agentdojo(facts: PolicyFactSet) -> bool:
    return bool(facts.find("agentdojo", "suite") or facts.find("agentdojo", "tool_call_boundary"))


def _either_untrusted(facts: PolicyFactSet) -> bool:
    return _bool(facts, "source", "has_untrusted") or _bool(facts, "agentdojo", "untrusted_observation_seen")


def _any(facts: PolicyFactSet, keys: list[tuple[str, str]]) -> bool:
    return any(_bool(facts, ns, key) for ns, key in keys)


def _value_in(facts: PolicyFactSet, namespace: str, key: str, values: set[str]) -> bool:
    return any(str(item.value).lower() in {value.lower() for value in values} for item in facts.find(namespace, key))
