"""Package-manager and software-supply-chain guard."""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Protocol

from .models import ActionIR, PackageEvent, new_id


class PackageCommandParser(Protocol):
    manager: str

    def targets(self, raw: str) -> list[str]: ...


class ShlexPackageCommandParser:
    manager = "generic"
    commands: set[str] = set()
    subcommands: set[str] = set()
    value_flags = {"-r", "--requirement", "--registry", "--index-url", "-i", "--extra-index-url", "--find-links", "-f"}
    boolean_flags = {"--package-lock-only", "--no-save", "--save-dev", "-D", "--dev", "--upgrade", "-U", "--editable", "-e"}

    def targets(self, raw: str) -> list[str]:
        try:
            tokens = shlex.split(raw)
        except ValueError:
            tokens = raw.split()
        targets: list[str] = []
        skip_next = False
        for token in tokens:
            low = token.lower()
            if skip_next:
                skip_next = False
                continue
            if low in self.commands or low in self.subcommands:
                continue
            if low in self.value_flags:
                skip_next = True
                continue
            if low.startswith("--") and "=" in low:
                flag, _value = low.split("=", 1)
                if flag in self.value_flags or flag in self.boolean_flags:
                    continue
            if low.startswith("-"):
                continue
            if token:
                targets.append(token)
        return targets


class NpmCommandParser(ShlexPackageCommandParser):
    manager = "npm"
    commands = {"npm", "pnpm", "yarn", "npx", "pnpm"}
    subcommands = {"install", "i", "add", "ci", "dlx", "exec"}


class PipCommandParser(ShlexPackageCommandParser):
    manager = "pip"
    commands = {"pip", "pip3", "python", "python3"}
    subcommands = {"install", "-m", "pip"}


class PoetryCommandParser(ShlexPackageCommandParser):
    manager = "poetry"
    commands = {"poetry"}
    subcommands = {"add", "install"}


class CargoCommandParser(ShlexPackageCommandParser):
    manager = "cargo"
    commands = {"cargo"}
    subcommands = {"add", "install"}


class GoCommandParser(ShlexPackageCommandParser):
    manager = "go"
    commands = {"go"}
    subcommands = {"get", "install"}


class PackageGuard:
    def __init__(self, repo_root: str | Path, allowed_registries: list[str] | None = None):
        self.repo_root = Path(repo_root)
        self.allowed_registries = allowed_registries or ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "fake-registry.local"]
        self.parsers: list[PackageCommandParser] = [
            NpmCommandParser(),
            PipCommandParser(),
            PoetryCommandParser(),
            CargoCommandParser(),
            GoCommandParser(),
        ]

    def analyze(self, action: ActionIR) -> PackageEvent | None:
        if (
            not action.semantic_action.startswith("install_")
            and action.semantic_action != "publish_artifact"
            and action.semantic_action != "modify_registry_config"
        ):
            return None
        if action.semantic_action == "publish_artifact":
            return PackageEvent(
                package_event_id=new_id("pkg"),
                action_id=action.action_id,
                event_type="publish_attempt",
                package=None,
                source="registry_publish",
                lifecycle_scripts=[],
                registry=self._registry_from_config() or "unknown",
                risk="critical",
                decision="double_approval_required",
                reason_codes=["publish_artifact", "supply_chain_boundary"],
            )
        if action.semantic_action == "modify_registry_config":
            return PackageEvent(
                package_event_id=new_id("pkg"),
                action_id=action.action_id,
                event_type="registry_config_change",
                package=None,
                source="registry_config",
                lifecycle_scripts=[],
                registry="changed_registry",
                risk="critical",
                decision="block_or_approval",
                reason_codes=["modify_registry_config"],
            )

        manager = self._manager_for_command(action.raw_action)
        targets = self._targets_for_command(action.raw_action, manager)
        if not targets:
            targets = action.metadata.get("package_args", []) if action.metadata else []
        package = targets[0] if targets else self._extract_package(action.raw_action)
        source = self._source_for_package(package or action.raw_action)
        lifecycle_scripts = self._lifecycle_scripts_for(package)
        registry = self._registry_from_command(action.raw_action) or self._registry_from_config() or "official_or_default"
        lockfile_reasons = self._lockfile_reasons(manager)
        metadata_reasons = self._local_metadata_reasons(manager, package)
        provenance_reasons = self._offline_provenance_reasons(package)
        reason_codes: list[str] = []
        risk = "high"
        decision = "approval_required"

        if source in {"git_url", "tarball_url"}:
            reason_codes.append(f"dependency_source_{source}")
            risk = "critical" if package and re.search(r"attacker|unknown|helper", package, re.I) else "high"
            decision = "block_or_high_approval"
        if lifecycle_scripts:
            reason_codes.append("lifecycle_script_possible")
            risk = "critical" if risk == "high" else risk
        if registry not in {"official_or_default", *self.allowed_registries}:
            reason_codes.append("registry_unknown_or_changed")
            risk = "critical"
        reason_codes.extend(lockfile_reasons)
        reason_codes.extend(metadata_reasons)
        reason_codes.extend(provenance_reasons)
        if any(r.startswith("package_provenance_denied") or r.startswith("package_reputation_low") for r in provenance_reasons):
            risk = "critical"
            decision = "block_or_high_approval"
        if "lockfile_missing" in lockfile_reasons and manager in {"npm", "poetry", "cargo", "go"}:
            decision = "approval_required_lockfile_diff"
        if not reason_codes:
            reason_codes.append("install_registry_dependency")

        return PackageEvent(
            package_event_id=new_id("pkg"),
            action_id=action.action_id,
            event_type="dependency_install",
            package=package,
            source=source,
            lifecycle_scripts=lifecycle_scripts,
            registry=registry,
            risk=risk,  # type: ignore[arg-type]
            decision=decision,
            reason_codes=reason_codes,
        )

    def _manager_for_command(self, raw: str) -> str:
        low = raw.lower()
        if re.search(r"\b(npm|pnpm|yarn|npx)\b", low):
            return "npm"
        if re.search(r"\b(pip|pip3|python\s+-m\s+pip)\b", low):
            return "pip"
        if re.search(r"\bpoetry\b", low):
            return "poetry"
        if re.search(r"\bcargo\b", low):
            return "cargo"
        if re.search(r"\bgo\s+(get|install)\b", low):
            return "go"
        return "generic"

    def _targets_for_command(self, raw: str, manager: str) -> list[str]:
        for parser in self.parsers:
            if parser.manager == manager:
                return parser.targets(raw)
        return []

    def _lockfile_reasons(self, manager: str) -> list[str]:
        lockfiles = {
            "npm": ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"],
            "pip": ["requirements.txt", "requirements.lock"],
            "poetry": ["poetry.lock"],
            "cargo": ["Cargo.lock"],
            "go": ["go.sum"],
        }.get(manager, [])
        if not lockfiles:
            return []
        existing = [name for name in lockfiles if (self.repo_root / name).exists()]
        if existing:
            return [f"lockfile_present:{name}" for name in existing]
        return ["lockfile_missing"]

    def _local_metadata_reasons(self, manager: str, package: str | None) -> list[str]:
        if not package:
            return ["package_target_unknown"]
        reasons: list[str] = []
        if manager == "npm":
            package_json = self.repo_root / "package.json"
            if package_json.exists():
                try:
                    data = json.loads(package_json.read_text(encoding="utf-8"))
                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    if package in deps:
                        reasons.append("package_already_declared")
                    else:
                        reasons.append("package_manifest_diff_required")
                except Exception:
                    reasons.append("package_manifest_unreadable")
            lock = self.repo_root / "package-lock.json"
            if lock.exists():
                try:
                    data = json.loads(lock.read_text(encoding="utf-8"))
                    packages = data.get("packages", {})
                    if f"node_modules/{package}" in packages:
                        reasons.append("lockfile_contains_target")
                    else:
                        reasons.append("lockfile_diff_target_missing")
                except Exception:
                    reasons.append("lockfile_unreadable")
        elif manager == "pip":
            req = self.repo_root / "requirements.txt"
            if req.exists():
                text = req.read_text(encoding="utf-8", errors="ignore").lower()
                normalized = package.split("==", 1)[0].lower()
                reasons.append("requirements_contains_target" if normalized in text else "requirements_diff_required")
        return reasons

    def _offline_provenance_reasons(self, package: str | None) -> list[str]:
        if not package:
            return []
        oracle = self.repo_root / ".agentbrake" / "package_metadata.json"
        if not oracle.exists():
            return ["package_metadata_unavailable"]
        try:
            data = json.loads(oracle.read_text(encoding="utf-8"))
        except Exception:
            return ["package_metadata_unreadable"]
        meta = data.get(package) or data.get(package.split("==", 1)[0])
        if not isinstance(meta, dict):
            return ["package_metadata_missing"]
        reasons: list[str] = []
        if meta.get("deny"):
            reasons.append("package_provenance_denied")
        if meta.get("reputation") == "low":
            reasons.append("package_reputation_low")
        if meta.get("sigstore") is True or meta.get("provenance") == "verified":
            reasons.append("package_provenance_verified")
        else:
            reasons.append("package_provenance_unverified")
        if meta.get("integrity"):
            reasons.append("package_integrity_pinned")
        return reasons

    def _extract_package(self, raw: str) -> str | None:
        m = re.search(r"\b(?:npm|pnpm|yarn|pip|pip3|poetry)\s+(?:install|i|add)\s+([^\s]+)", raw, re.I)
        return m.group(1) if m else None

    def _source_for_package(self, package: str | None) -> str:
        if not package:
            return "unknown"
        p = package.lower()
        if p.startswith(("git+", "git@")) or p.startswith("github:"):
            return "git_url"
        if p.startswith(("http://", "https://")) or p.endswith(".tgz") or p.endswith(".tar.gz"):
            return "tarball_url"
        if p.startswith("-r"):
            return "requirements_file"
        return "registry"

    def _registry_from_command(self, raw: str) -> str | None:
        m = re.search(r"--registry[=\s]+([^\s]+)", raw, re.I)
        if not m:
            m = re.search(r"--index-url[=\s]+([^\s]+)", raw, re.I)
        if not m:
            m = re.search(r"--extra-index-url[=\s]+([^\s]+)", raw, re.I)
        if not m:
            return None
        return re.sub(r"^https?://", "", m.group(1)).split("/")[0]

    def _registry_from_config(self) -> str | None:
        for config in [self.repo_root / ".npmrc", self.repo_root / ".pypirc"]:
            if not config.exists():
                continue
            try:
                text = config.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            m = re.search(r"registry\s*=\s*(https?://)?([^/\s]+)", text, re.I)
            if m:
                return m.group(2)
        return None

    def _lifecycle_scripts_for(self, package: str | None) -> list[str]:
        scripts: list[str] = []
        manifest = self.repo_root / "package.json"
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                local_scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
                scripts.extend([name for name in ["preinstall", "install", "postinstall", "prepare"] if name in local_scripts])
            except Exception:
                pass
        if package and re.search(r"attacker|unknown|helper", package, re.I):
            if "postinstall" not in scripts:
                scripts.append("postinstall")
        return scripts
