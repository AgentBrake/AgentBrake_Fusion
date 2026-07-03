from __future__ import annotations

from typing import Any

from .base import PolicyFinding


class WorkspacePolicyEngine:
    name = "workspace"
    suites = {"workspace"}

    def evaluate(self, *, facts: dict[str, Any], graph: dict[str, Any], context: Any) -> list[PolicyFinding]:
        findings: list[PolicyFinding] = []
        if (
            facts.get("agentdojo.tool_group") == "external_send"
            and facts.get("agentdojo.untrusted_seen")
            and not facts.get("agentdojo.args_match_user_entity")
            and not facts.get("agentdojo.task_authorized")
            and not _trusted_workspace_action(facts)
        ):
            findings.append(
                PolicyFinding(
                    engine=self.name,
                    decision="block",
                    confidence=0.8,
                    reason_codes=["ADJ-MSG-001"],
                    metadata={"reason": "untrusted context attempted unauthorized external send"},
                )
            )
        if (
            facts.get("agentdojo.tool_group") in {"calendar_mutation", "file_mutation"}
            and not facts.get("agentdojo.task_authorized")
            and not _trusted_workspace_action(facts)
        ):
            findings.append(
                PolicyFinding(
                    engine=self.name,
                    decision="require_confirmation",
                    confidence=0.65,
                    reason_codes=["ADJ-WORKSPACE-CONFIRM-STATE-MUTATION"],
                    metadata={"reason": "workspace state mutation requires confirmation"},
                )
            )
        return findings


def _trusted_workspace_action(facts: dict[str, Any]) -> bool:
    return bool(
        "tool_group_authorized_by_task" in (facts.get("agentdojo.authorization_reasons") or [])
        and not _current_args_overlap_suspicious_targets(facts)
    )


def _current_args_overlap_suspicious_targets(facts: dict[str, Any]) -> bool:
    arg_text = repr(facts.get("agentdojo.arg_entities") or {}).lower()
    for target in facts.get("agentdojo.suspicious_targets") or []:
        normalized = str(target).lower().strip(" .,\n\t\\'\"")
        if len(normalized) < 4 or normalized in {"using", "with", "from", "that", "this", "after", "before"}:
            continue
        if normalized in arg_text:
            return True
    return False
