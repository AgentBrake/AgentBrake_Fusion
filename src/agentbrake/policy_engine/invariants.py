"""Non-downgradable safety invariants for the MSJ Engine."""

from __future__ import annotations

from .facts import PolicyFactSet
from .rule_schema import RuleHit
from .semantic_invariants import SemanticInvariantRegistry


class InvariantEngine:
    """Compatibility facade backed by the semantic invariant registry."""

    def __init__(self) -> None:
        self.registry = SemanticInvariantRegistry()
        self.version = self.registry.version

    def evaluate(self, facts: PolicyFactSet) -> list[RuleHit]:
        return self.registry.evaluate(facts)
