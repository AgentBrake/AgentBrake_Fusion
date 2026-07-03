"""Two-layer AgentBrake-Fusion registry: immutable source rules + user/project overrides."""

from __future__ import annotations

import fnmatch
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Any


@dataclass(slots=True)
class RegistryRule:
    pattern: str
    confidentiality: str = "LOW"
    trust: str = "semi_trusted"
    risk: str = "medium"
    capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class TwoLayerRegistry:
    def __init__(self) -> None:
        self.source_rules: list[RegistryRule] = [
            RegistryRule(".env*", "HIGH", "semi_trusted", "critical", ["secret"]),
            RegistryRule(".npmrc", "HIGH", "semi_trusted", "critical", ["publish_config"]),
            RegistryRule(".pypirc", "HIGH", "semi_trusted", "critical", ["publish_config"]),
            RegistryRule(".ssh/**", "HIGH", "semi_trusted", "critical", ["secret"]),
            RegistryRule(".github/workflows/**", "MEDIUM", "semi_trusted", "high", ["ci_cd"]),
            RegistryRule("package.json", "LOW", "semi_trusted", "high", ["package_manifest"]),
            RegistryRule("pyproject.toml", "LOW", "semi_trusted", "high", ["package_manifest"]),
        ]
        self.user_rules: list[RegistryRule] = []

    def add_user_rule(self, rule: RegistryRule) -> None:
        self.user_rules.append(rule)

    def classify_path(self, path: str) -> dict[str, Any]:
        norm = self._norm(path)
        # User layer wins for explicit taint/project overrides; otherwise source rules apply.
        for rule in reversed(self.user_rules):
            if fnmatch.fnmatch(norm, self._norm(rule.pattern)):
                return {"path": norm, "layer": "user", **asdict(rule)}
        for rule in self.source_rules:
            if fnmatch.fnmatch(norm, self._norm(rule.pattern)):
                return {"path": norm, "layer": "source", **asdict(rule)}
        return {
            "path": norm,
            "layer": "default",
            "pattern": "*",
            "confidentiality": "LOW",
            "trust": "semi_trusted",
            "risk": "low",
            "capabilities": [],
            "metadata": {},
        }

    @staticmethod
    def _norm(path: str) -> str:
        return str(PurePosixPath(path.replace("\\", "/"))).lstrip("/")
