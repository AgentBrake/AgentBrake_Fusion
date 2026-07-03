"""Context provenance and trust tagging."""

from __future__ import annotations

import re
from pathlib import Path

from .models import ContextGraph, SourceRecord, TrustLevel, new_id, sha256_text, utc_now

TRUST_BY_SOURCE_TYPE: dict[str, TrustLevel] = {
    "system_policy": "admin",
    "admin_config": "admin",
    "user_request": "trusted",
    "explicit_user_instruction": "trusted",
    "repo_source_file": "semi_trusted",
    "readme": "semi_trusted",
    "project_rule": "semi_trusted",
    "github_issue_title": "untrusted",
    "github_issue_body": "untrusted",
    "pr_comment": "untrusted",
    "branch_name": "untrusted",
    "commit_message": "untrusted",
    "web_page": "untrusted",
    "mcp_output": "tool_untrusted",
    "ci_log": "untrusted",
    "package_output": "untrusted",
    "memory": "tainted",
    "quoted_external": "untrusted",
}

INSTRUCTION_LIKE_RE = re.compile(
    r"\b(ignore|run|execute|install|curl|wget|cat\s+\.env|printenv|token|secret|deploy|publish|chmod|rm\s+-rf|bash|powershell)\b",
    re.I,
)


class ContextProvenance:
    """Create SourceRecords and preserve source lineage through transformations."""

    def __init__(self) -> None:
        self.graph = ContextGraph()

    def ingest(self, source_type: str, content: str, retrieval_path: str = "", source_id: str | None = None) -> SourceRecord:
        trust = TRUST_BY_SOURCE_TYPE.get(source_type, "unknown")
        taint: list[str] = []
        if trust in {"untrusted", "tool_untrusted", "tainted", "unknown"}:
            taint.append("external_text")
        if INSTRUCTION_LIKE_RE.search(content):
            taint.append("instruction_like")
        allowed_use, forbidden_use = self._uses_for_trust(trust)
        record = SourceRecord(
            source_id=source_id or new_id("src"),
            source_type=source_type,
            trust_level=trust,
            content_hash=sha256_text(content),
            retrieved_at=utc_now(),
            retrieval_path=retrieval_path or source_type,
            taint=taint,
            allowed_use=allowed_use,
            forbidden_use=forbidden_use,
            content_preview=content[:240],
        )
        self.graph.nodes.append(record)
        return record

    def ingest_file(self, path: str | Path, source_type: str | None = None, source_id: str | None = None) -> SourceRecord:
        path = Path(path)
        content = path.read_text(encoding="utf-8")
        inferred = source_type or self._infer_source_type(path)
        return self.ingest(inferred, content, str(path), source_id=source_id)

    def derive(self, parent_source_ids: list[str], derived_text: str, source_type: str = "derived_summary") -> SourceRecord:
        # Derived text keeps the least trusted parent as its trust floor.
        parent_levels = [self.graph.get(s).trust_level for s in parent_source_ids if self.graph.get(s)]
        trust = self._trust_floor(parent_levels) if parent_levels else "unknown"
        taint = ["derived"]
        if trust in {"untrusted", "tool_untrusted", "tainted", "unknown"}:
            taint.append("external_text")
        if INSTRUCTION_LIKE_RE.search(derived_text):
            taint.append("instruction_like")
        allowed_use, forbidden_use = self._uses_for_trust(trust)
        record = SourceRecord(
            source_id=new_id("src"),
            source_type=source_type,
            trust_level=trust,
            content_hash=sha256_text(derived_text),
            retrieved_at=utc_now(),
            retrieval_path=f"derived_from:{','.join(parent_source_ids)}",
            taint=taint,
            allowed_use=allowed_use,
            forbidden_use=forbidden_use,
            derived_from=list(parent_source_ids),
            content_preview=derived_text[:240],
        )
        self.graph.nodes.append(record)
        for parent in parent_source_ids:
            self.graph.edges.append({"from": parent, "to": record.source_id, "relation": "derived_from"})
        return record

    def influence(self, source_id: str, action_id: str) -> None:
        self.graph.edges.append({"from": source_id, "to": action_id, "relation": "influenced"})

    @staticmethod
    def _infer_source_type(path: Path) -> str:
        name = path.name.lower()
        if name in {"readme.md", "readme.txt"}:
            return "readme"
        if name in {"claude.md", "agents.md", ".cursorrules"}:
            return "project_rule"
        if "issue" in name:
            return "github_issue_body"
        if "branch" in name:
            return "branch_name"
        return "repo_source_file"

    @staticmethod
    def _uses_for_trust(trust: TrustLevel) -> tuple[list[str], list[str]]:
        if trust == "admin":
            return ["configure_policy", "authorize_tool_use"], []
        if trust == "trusted":
            return ["authorize_task", "summarize", "classify", "quote"], ["override_admin_policy"]
        if trust == "semi_trusted":
            return ["understand_project", "summarize", "quote"], ["override_admin_policy", "authorize_high_risk_tool_use"]
        return ["summarize", "classify", "quote", "forensic_reference"], [
            "execute_as_instruction",
            "authorize_tool_use",
            "override_policy",
            "authorize_dependency_install",
            "authorize_network_egress",
        ]

    @staticmethod
    def _trust_floor(levels: list[TrustLevel]) -> TrustLevel:
        order: list[TrustLevel] = ["admin", "trusted", "semi_trusted", "untrusted", "tool_untrusted", "tainted", "unknown"]
        if not levels:
            return "unknown"
        return max(levels, key=lambda t: order.index(t) if t in order else len(order))
