"""Typed facts used by the MSJ Engine fact space."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..models import new_id, sha256_json


@dataclass(slots=True)
class PolicyFact:
    fact_id: str
    namespace: str
    key: str
    value: Any
    evidence_refs: list[str] = field(default_factory=list)
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def of(
        cls,
        namespace: str,
        key: str,
        value: Any,
        *,
        evidence_refs: list[str] | None = None,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> "PolicyFact":
        return cls(
            fact_id=new_id("fact"),
            namespace=namespace,
            key=key,
            value=value,
            evidence_refs=evidence_refs or [],
            confidence=confidence,
            metadata=metadata or {},
        )


@dataclass(slots=True)
class PolicyFactSet:
    facts: list[PolicyFact]
    fact_set_id: str = ""
    content_hash: str = ""

    def __post_init__(self) -> None:
        payload = [asdict(f) for f in self.facts]
        # Ignore generated fact ids for stable comparison across runs.
        stable_payload = [{k: v for k, v in item.items() if k != "fact_id"} for item in payload]
        self.content_hash = sha256_json(stable_payload)
        self.fact_set_id = f"factset_{self.content_hash.removeprefix('sha256:')[:16]}"

    def find(self, namespace: str, key: str | None = None) -> list[PolicyFact]:
        return [f for f in self.facts if f.namespace == namespace and (key is None or f.key == key)]

    def any_value(self, namespace: str, key: str, values: set[Any]) -> bool:
        return any(f.value in values for f in self.find(namespace, key))

    def values(self, namespace: str, key: str) -> list[Any]:
        return [f.value for f in self.find(namespace, key)]

    def to_summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for fact in self.facts:
            counts[fact.namespace] = counts.get(fact.namespace, 0) + 1
        return {
            "fact_set_id": self.fact_set_id,
            "content_hash": self.content_hash,
            "fact_count": len(self.facts),
            "namespace_counts": counts,
        }
