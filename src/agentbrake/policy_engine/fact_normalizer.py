"""Normalize PolicyFact values into stable index keys."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .fact_registry import FACT_KEY_REGISTRY, FactKeySpec
from .facts import PolicyFact, PolicyFactSet


@dataclass(frozen=True, slots=True)
class IndexKey:
    path: str
    value: str
    kind: str

    def token(self) -> str:
        return f"{self.path}={self.value}"


class FactNormalizer:
    def __init__(self, registry: dict[str, FactKeySpec] | None = None) -> None:
        self.registry = registry or FACT_KEY_REGISTRY

    def keys_for_fact_set(self, facts: PolicyFactSet) -> set[IndexKey]:
        keys: set[IndexKey] = set()
        for fact in facts.facts:
            keys.update(self.index_keys(fact))
        return keys

    def index_keys(self, fact: PolicyFact) -> list[IndexKey]:
        path = f"{fact.namespace}.{fact.key}"
        spec = self.registry.get(path)
        if spec is None:
            return []
        values = _as_list(fact.value)
        if spec.index_strategy == "presence":
            return [IndexKey(path, "__exists__", "presence")]
        if spec.index_strategy in {"list_each", "exact", "boolean"}:
            kind = "list_each" if spec.index_strategy == "list_each" else "exact"
            return [IndexKey(path, _canonical(value), kind) for value in values]
        if spec.index_strategy == "range_bucket":
            return [IndexKey(path, _range_bucket(value), "range") for value in values]
        return []


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple) or isinstance(value, set):
        return list(value)
    return [value]


def _canonical(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value).strip().lower()


def _range_bucket(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "unknown"
    if number < 0.25:
        return "lt_0_25"
    if number < 0.5:
        return "lt_0_5"
    if number < 0.75:
        return "lt_0_75"
    return "gte_0_75"


def canonical_expected_values(value: Any) -> list[str]:
    return [_canonical(v) for v in _as_list(value)]
