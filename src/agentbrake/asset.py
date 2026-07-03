"""Repository asset and attack-surface scanner."""

from __future__ import annotations

import os
import re
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .models import AssetRecord, RepoAssetGraph, RiskSurfaceReport, new_id

SECRET_ENV_RE = re.compile(r"(TOKEN|SECRET|PASSWORD|PRIVATE_KEY|ACCESS_KEY|API_KEY|AUTH)", re.I)
ENV_FILE_RE = re.compile(r"^\.env(\..*)?$", re.I)
SSH_KEY_RE = re.compile(r"^(id_rsa|id_ed25519|id_ecdsa|.*\.pem)$", re.I)
IGNORED_DIR_NAMES = {
    ".git",
    ".hypothesis",
    ".mypy_cache",
    ".pytest_cache",
    ".agentbrake",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    "reports",
    "venv",
}

DEFAULT_CAPABILITIES = [
    {"tool": "Read", "capability": "read_file", "risk": "medium"},
    {"tool": "Edit", "capability": "write_file", "risk": "medium"},
    {"tool": "Bash", "capability": "execute_command", "risk": "high"},
    {"tool": "MCP.read_issue", "capability": "external_read", "risk": "medium"},
]


class AssetScanner:
    """Scan a repository and produce a RepoAssetGraph.

    The scanner intentionally fails closed: permission errors and symlink loops
    are recorded as visibility gaps instead of being treated as safe.
    """

    def __init__(self, repo_root: str | Path, env: dict[str, str] | None = None, agent_capabilities: list[dict] | None = None):
        self.repo_root = Path(repo_root).resolve()
        self.env = env if env is not None else dict(os.environ)
        self.agent_capabilities = agent_capabilities or DEFAULT_CAPABILITIES

    def scan(self) -> RepoAssetGraph:
        graph = RepoAssetGraph(repo_root=str(self.repo_root))
        graph.agent_capabilities = list(self.agent_capabilities)
        graph.external_sinks = [
            {"type": "network", "default_policy": "deny"},
            {"type": "registry_publish", "default_policy": "approval_required"},
            {"type": "git_remote", "default_policy": "approval_required"},
        ]

        for item in self._iter_paths():
            try:
                record = self._classify_path(item)
                if record:
                    graph.assets.append(record)
                    if record.risk == "critical" or record.asset_type in {"secret_file", "secret_env", "publish_config"}:
                        graph.sensitive_assets.append(record)
                    if record.risk in {"high", "critical"} and record.asset_type not in {"secret_env"}:
                        graph.critical_files.append(record)
            except OSError as exc:
                graph.visibility_gaps.append(
                    {
                        "path": self._rel(item),
                        "reason": type(exc).__name__,
                        "policy": "raise_risk_for_related_actions",
                    }
                )

        for name in sorted(self.env):
            if SECRET_ENV_RE.search(name):
                record = AssetRecord(
                    asset_id=new_id("asset"),
                    path=f"env:{name}",
                    canonical_path=f"env:{name}",
                    asset_type="secret_env",
                    risk="critical",
                    owner="environment",
                    protection_policy=["redact", "no_egress_after_touch", "block_direct_read"],
                    metadata={"env_present": True},
                )
                graph.assets.append(record)
                graph.sensitive_assets.append(record)

        return graph.finalise()

    def report(self, graph: RepoAssetGraph) -> RiskSurfaceReport:
        critical = sum(1 for a in graph.assets if a.risk == "critical")
        high = sum(1 for a in graph.assets if a.risk == "high")
        publish_assets = sum(1 for a in graph.assets if a.asset_type in {"publish_config", "ci_workflow"})
        lifecycle = 0
        for asset in graph.assets:
            if asset.asset_type == "package_manifest" and asset.metadata.get("lifecycle_scripts"):
                lifecycle += 1
        return RiskSurfaceReport(
            critical_count=critical,
            high_count=high,
            publish_assets=publish_assets,
            package_lifecycle_risks=lifecycle,
            visibility_gap_count=len(graph.visibility_gaps),
            summary=(
                f"当前仓库有 {critical} 个 critical assets、{publish_assets} 个发布/CI 相关资产、"
                f"{lifecycle} 个 package lifecycle 风险、{len(graph.visibility_gaps)} 个扫描缺口。"
            ),
        )

    def _iter_paths(self) -> Iterable[Path]:
        if not self.repo_root.exists():
            raise FileNotFoundError(self.repo_root)
        for root, dirs, files in os.walk(self.repo_root, followlinks=False):
            root_path = Path(root)
            # Keep hidden files, skip huge/generated directories that do not add value to the MVP scanner.
            dirs[:] = [d for d in dirs if not _should_skip_dir(d)]
            for name in files:
                yield root_path / name
            for name in dirs:
                path = root_path / name
                if path.is_symlink():
                    yield path

    def _rel(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.repo_root).as_posix()
        except Exception:
            try:
                return path.relative_to(self.repo_root).as_posix()
            except Exception:
                return str(path)

    def _classify_path(self, path: Path) -> AssetRecord | None:
        rel = self._rel(path)
        name = path.name
        rel_lower = rel.lower()
        canonical = str(path.resolve(strict=False))
        metadata: dict = {}

        if path.is_symlink():
            target = path.resolve(strict=False)
            outside = not str(target).startswith(str(self.repo_root))
            return AssetRecord(
                asset_id=new_id("asset"),
                path=rel,
                canonical_path=str(target),
                asset_type="symlink",
                risk="high" if outside else "medium",
                confidence=0.9,
                protection_policy=["no_follow_without_policy"] if outside else ["track_target"],
                metadata={"symlink_target": str(target), "points_outside_repo": outside},
            )

        if ENV_FILE_RE.match(name) or SSH_KEY_RE.match(name):
            return AssetRecord(
                asset_id=new_id("asset"),
                path=rel,
                canonical_path=canonical,
                asset_type="secret_file",
                risk="critical",
                protection_policy=["block_direct_read", "mask_in_sandbox", "no_egress_after_touch"],
            )

        if name in {".npmrc", ".pypirc"}:
            return AssetRecord(
                asset_id=new_id("asset"),
                path=rel,
                canonical_path=canonical,
                asset_type="publish_config",
                risk="critical",
                protection_policy=["block_or_approval", "mask_in_sandbox", "track_registry_config"],
            )

        if rel_lower.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
            return AssetRecord(
                asset_id=new_id("asset"),
                path=rel,
                canonical_path=canonical,
                asset_type="ci_workflow",
                risk="high",
                protection_policy=["approval_required", "record_diff"],
            )

        if name in {"package.json", "pyproject.toml", "setup.py", "setup.cfg"}:
            lifecycle = self._detect_lifecycle_scripts(path)
            metadata["lifecycle_scripts"] = lifecycle
            return AssetRecord(
                asset_id=new_id("asset"),
                path=rel,
                canonical_path=canonical,
                asset_type="package_manifest",
                risk="high",
                protection_policy=["package_preflight", "approval_for_script_changes"],
                metadata=metadata,
            )

        if name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "requirements.txt", "Pipfile.lock"}:
            return AssetRecord(
                asset_id=new_id("asset"),
                path=rel,
                canonical_path=canonical,
                asset_type="lockfile",
                risk="medium",
                protection_policy=["lockfile_diff_oracle"],
            )

        if rel_lower.startswith(("scripts/", "bin/")) and name.endswith((".sh", ".bash", ".py", ".js")):
            return AssetRecord(
                asset_id=new_id("asset"),
                path=rel,
                canonical_path=canonical,
                asset_type="executable_script",
                risk="medium",
                protection_policy=["record_diff", "approval_if_publish_or_network"],
            )

        if name in {"Makefile", "Dockerfile"}:
            return AssetRecord(
                asset_id=new_id("asset"),
                path=rel,
                canonical_path=canonical,
                asset_type="executable_script",
                risk="high" if name == "Dockerfile" else "medium",
                protection_policy=["record_diff", "sandbox_tests"],
            )

        if rel_lower in {".mcp/config.json", "mcp.json"} or "/.mcp/" in rel_lower:
            return AssetRecord(
                asset_id=new_id("asset"),
                path=rel,
                canonical_path=canonical,
                asset_type="mcp_config",
                risk="high",
                protection_policy=["mcp_proxy_required", "no_token_passthrough"],
            )

        return None

    def _detect_lifecycle_scripts(self, path: Path) -> list[str]:
        if path.name != "package.json":
            return []
        try:
            import json

            data = json.loads(path.read_text(encoding="utf-8"))
            scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
            return [s for s in ("preinstall", "install", "postinstall", "prepublish", "prepare") if s in scripts]
        except Exception:
            return []


def graph_to_jsonable(graph: RepoAssetGraph) -> dict:
    return asdict(graph)


def _should_skip_dir(name: str) -> bool:
    return name in IGNORED_DIR_NAMES or name.startswith(".pytest_tmp") or name.startswith("reports_tmp")
