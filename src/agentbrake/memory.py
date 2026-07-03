"""Long-term memory write/read gates with trust inheritance."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .context import ContextProvenance
from .models import ContextGraph, MemoryRecord, SourceRecord, TrustLevel, new_id, sha256_text, utc_now

TRUST_ORDER: list[TrustLevel] = ["admin", "trusted", "semi_trusted", "untrusted", "tool_untrusted", "tainted", "unknown"]
HIGH_RISK_AUTH_USES = {
    "authorize_dependency_install",
    "authorize_network_egress",
    "authorize_publish",
    "override_policy",
    "authorize_ci_modify",
}
SENSITIVE_WORDS = ["token", "secret", "install", "curl", "deploy", "publish", "registry", "workflow", "github:", "npmrc", "pypirc"]


class MemoryStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]", encoding="utf-8")

    def write(
        self,
        summary: str,
        source_ids: list[str],
        context_graph: ContextGraph,
        created_by: str = "agent",
        ttl_seconds: int = 86400,
        write_decision_id: str | None = None,
    ) -> MemoryRecord:
        trust_floor = self._trust_floor([context_graph.get(s).trust_level for s in source_ids if context_graph.get(s)])
        tainted = trust_floor in {"untrusted", "tool_untrusted", "tainted", "unknown"}
        sensitive_keywords = any(word in summary.lower() for word in SENSITIVE_WORDS)
        memory_trust: TrustLevel = "tainted" if tainted or sensitive_keywords else trust_floor
        allowed = ["forensic_reference", "summarize"] if memory_trust == "tainted" else ["recall_project_context", "summarize"]
        forbidden = (
            ["authorize_dependency_install", "override_policy", "authorize_network_egress", "authorize_publish", "authorize_ci_modify"]
            if memory_trust == "tainted"
            else ["override_admin_policy"]
        )
        record = MemoryRecord(
            memory_id=new_id("mem"),
            content_hash=sha256_text(summary),
            summary=summary,
            source_ids=list(source_ids),
            source_trust_floor=trust_floor,
            memory_trust=memory_trust,
            allowed_use=allowed,
            forbidden_use=forbidden,
            ttl_seconds=ttl_seconds,
            created_at=utc_now(),
            created_by=created_by,
            write_decision_id=write_decision_id,
        )
        data = self._load()
        data.append(asdict(record))
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return record

    def read_as_context(self, memory_id: str, provenance: ContextProvenance) -> SourceRecord | None:
        record = self.get(memory_id)
        if not record or self._expired(record):
            return None
        src = provenance.ingest("memory", record["summary"], retrieval_path=f"memory:{memory_id}", source_id=f"src_{memory_id}")
        src.trust_level = record.get("memory_trust", "tainted")
        src.derived_from = record.get("source_ids", [])
        src.allowed_use = record.get("allowed_use", [])
        src.forbidden_use = record.get("forbidden_use", [])
        return src

    def get(self, memory_id: str) -> dict | None:
        return next((r for r in self._load() if r.get("memory_id") == memory_id), None)

    def list_active(self) -> list[dict]:
        return [r for r in self._load() if not self._expired(r)]

    def can_authorize(self, memory_id: str, use: str) -> tuple[bool, str]:
        record = self.get(memory_id)
        if not record:
            return False, "memory_missing"
        if self._expired(record):
            return False, "ttl_expired"
        if use in set(record.get("forbidden_use", [])) or (record.get("memory_trust") == "tainted" and use in HIGH_RISK_AUTH_USES):
            return False, "tainted_memory_cannot_authorize_high_risk_action"
        if use in set(record.get("allowed_use", [])):
            return True, "memory_use_allowed"
        return False, "memory_use_not_granted"

    def quarantine(self, memory_id: str, reason: str = "manual_quarantine") -> bool:
        data = self._load()
        changed = False
        for record in data:
            if record.get("memory_id") == memory_id:
                record["memory_trust"] = "tainted"
                record.setdefault("forbidden_use", [])
                for item in HIGH_RISK_AUTH_USES:
                    if item not in record["forbidden_use"]:
                        record["forbidden_use"].append(item)
                record["quarantine_reason"] = reason
                changed = True
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return changed

    def revoke(self, memory_id: str) -> bool:
        data = self._load()
        new_data = [r for r in data if r.get("memory_id") != memory_id]
        self.path.write_text(json.dumps(new_data, ensure_ascii=False, indent=2), encoding="utf-8")
        return len(new_data) != len(data)

    def _load(self) -> list[dict]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    @staticmethod
    def _expired(record: dict) -> bool:
        created = datetime.fromisoformat(record["created_at"])
        ttl = timedelta(seconds=int(record.get("ttl_seconds", 86400)))
        return datetime.now(timezone.utc) > created + ttl

    @staticmethod
    def _trust_floor(levels: list[TrustLevel]) -> TrustLevel:
        if not levels:
            return "unknown"
        return max(levels, key=lambda t: TRUST_ORDER.index(t) if t in TRUST_ORDER else len(TRUST_ORDER))
