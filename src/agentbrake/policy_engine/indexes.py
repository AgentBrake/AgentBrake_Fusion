"""Indexes over repository assets and source provenance."""

from __future__ import annotations

import fnmatch
from pathlib import Path, PurePosixPath
from typing import Any

from ..models import AssetRecord, ContextGraph, RepoAssetGraph, TrustLevel

TRUST_ORDER: dict[TrustLevel, int] = {
    "admin": 0,
    "trusted": 1,
    "semi_trusted": 2,
    "untrusted": 3,
    "tool_untrusted": 4,
    "tainted": 5,
    "unknown": 6,
}
UNTRUSTED_LEVELS = {"untrusted", "tool_untrusted", "tainted", "unknown"}


class AssetIndex:
    def __init__(self, graph: RepoAssetGraph):
        self.graph = graph
        self.repo_root = Path(graph.repo_root).resolve()
        self.by_path = {self._norm(a.path): a for a in graph.assets}
        self.by_canonical = {self._norm(a.canonical_path): a for a in graph.assets}
        self.by_type: dict[str, list[AssetRecord]] = {}
        for asset in graph.assets:
            self.by_type.setdefault(asset.asset_type, []).append(asset)

    def classify_path(self, path: str) -> dict[str, Any]:
        norm = self._norm(path)
        repo_escape = False
        try:
            if norm.startswith("env:"):
                rel = norm
            else:
                p = Path(path)
                resolved = (self.repo_root / p).resolve(strict=False) if not p.is_absolute() else p.resolve(strict=False)
                rel = resolved.relative_to(self.repo_root).as_posix()
        except Exception:
            rel = norm
            repo_escape = bool(path and not norm.startswith(("env:", "http:", "https:")))

        asset = (
            self.by_path.get(rel)
            or self.by_path.get(norm)
            or self.by_canonical.get(norm)
            or self.graph.asset_for_path(rel)
            or self.graph.asset_for_path(norm)
        )
        symlink_escape = bool(asset and asset.asset_type == "symlink" and asset.metadata.get("points_outside_repo"))
        if norm.startswith("../") or "/../" in norm:
            repo_escape = True
        return {
            "path": rel,
            "asset": asset,
            "asset_type": asset.asset_type if asset else None,
            "asset_risk": asset.risk if asset else None,
            "repo_escape": repo_escape,
            "symlink_escape": symlink_escape,
        }

    @staticmethod
    def forbidden_match(path: str, patterns: list[str]) -> bool:
        norm = str(PurePosixPath(path.replace("\\", "/"))).lstrip("/")
        return any(fnmatch.fnmatch(norm, str(PurePosixPath(p.replace("\\", "/"))).lstrip("/")) for p in patterns)

    @staticmethod
    def _norm(path: str) -> str:
        return str(path).replace("\\", "/").strip().lstrip("./")


class SourceIndex:
    def __init__(self, graph: ContextGraph):
        self.graph = graph
        self.by_id = {node.source_id: node for node in graph.nodes}

    def trust_floor(self, source_ids: list[str]) -> TrustLevel:
        levels = [self.by_id[sid].trust_level if sid in self.by_id else "unknown" for sid in source_ids]
        if not levels:
            return "trusted"
        return max(levels, key=lambda level: TRUST_ORDER[level])

    def has_untrusted(self, source_ids: list[str]) -> bool:
        return self.trust_floor(source_ids) in UNTRUSTED_LEVELS

    def facts_for(self, source_ids: list[str]) -> dict[str, Any]:
        floor = self.trust_floor(source_ids)
        return {
            "source_ids": source_ids,
            "trust_floor": floor,
            "has_untrusted": floor in UNTRUSTED_LEVELS,
            "taints": [taint for sid in source_ids for taint in (self.by_id.get(sid).taint if self.by_id.get(sid) else [])],
        }
