"""Optional host-agent configuration apply/restore helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .profiles import AgentProfile

LEGACY_MANIFEST_NAME = "agent-config-backup.json"


@dataclass(slots=True)
class AgentConfigChange:
    agent: str
    applied: bool
    restored: bool
    target: str
    backup: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "applied": self.applied,
            "restored": self.restored,
            "target": self.target,
            "backup": self.backup,
            "detail": self.detail,
        }


def apply_agent_config(repo: Path, config: dict[str, Any], profile: AgentProfile, *, force: bool = False) -> AgentConfigChange:
    if profile.agent != "codex":
        return _write_snippet(repo, config, profile, force=force)
    target = Path.home() / ".codex" / "config.toml"
    backup = repo / ".agentbrake" / "backups" / "codex-config.toml.bak"
    target.parent.mkdir(parents=True, exist_ok=True)
    backup.parent.mkdir(parents=True, exist_ok=True)
    original = target.read_text(encoding="utf-8") if target.exists() else ""
    if backup.exists() and not force:
        return AgentConfigChange(profile.agent, False, False, str(target), str(backup), "backup exists; pass --force to overwrite")
    backup.write_text(original, encoding="utf-8")
    target.write_text(_render_codex_config(config, original), encoding="utf-8")
    _write_manifest(repo, profile, target, backup, existed=bool(original))
    return AgentConfigChange(profile.agent, True, False, str(target), str(backup), "codex config applied")


def restore_agent_config(repo: Path, profile: AgentProfile) -> AgentConfigChange:
    manifest = _manifest_path(repo, profile.agent)
    if not manifest.exists():
        legacy = _legacy_manifest_path(repo)
        if not legacy.exists():
            return AgentConfigChange(profile.agent, False, False, "", "", "no agent config backup manifest")
        manifest = legacy
    data = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_agent = str(data.get("agent") or "")
    if manifest_agent and manifest_agent != profile.agent:
        return AgentConfigChange(profile.agent, False, False, "", "", "no agent config backup manifest")
    target = Path(str(data.get("target") or ""))
    backup = Path(str(data.get("backup") or ""))
    if not target or not backup.exists():
        return AgentConfigChange(profile.agent, False, False, str(target), str(backup), "backup target is missing")
    if data.get("existed"):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
    else:
        target.unlink(missing_ok=True)
    manifest.unlink(missing_ok=True)
    return AgentConfigChange(profile.agent, False, True, str(target), str(backup), "agent config restored")


def _write_snippet(repo: Path, config: dict[str, Any], profile: AgentProfile, *, force: bool) -> AgentConfigChange:
    target = repo / ".agentbrake" / "agent-config" / f"{profile.agent}.env"
    backup = repo / ".agentbrake" / "backups" / f"{profile.agent}.env.bak"
    target.parent.mkdir(parents=True, exist_ok=True)
    backup.parent.mkdir(parents=True, exist_ok=True)
    existed_before = target.exists()
    if existed_before:
        if backup.exists() and not force:
            return AgentConfigChange(profile.agent, False, False, str(target), str(backup), "backup exists; pass --force to overwrite")
        backup.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
    else:
        backup.write_text("", encoding="utf-8")
    target.write_text(_render_openai_env(config, profile), encoding="utf-8")
    _write_manifest(repo, profile, target, backup, existed=existed_before)
    return AgentConfigChange(profile.agent, True, False, str(target), str(backup), "agent env snippet written")


def _write_manifest(repo: Path, profile: AgentProfile, target: Path, backup: Path, *, existed: bool) -> None:
    path = _manifest_path(repo, profile.agent)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "agent": profile.agent,
                "target": str(target),
                "backup": str(backup),
                "existed": existed,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _manifest_path(repo: Path, agent: str) -> Path:
    return repo / ".agentbrake" / "backups" / f"{agent}-agent-config-backup.json"


def _legacy_manifest_path(repo: Path) -> Path:
    return repo / ".agentbrake" / LEGACY_MANIFEST_NAME


def _render_codex_config(config: dict[str, Any], original: str) -> str:
    gateway = config["gateway"]
    session = config["session"]
    block = "\n".join(
        [
            "# BEGIN AgentBrake-Fusion managed block",
            'model = "AgentBrake-Fusion/local-heuristic"',
            'model_provider = "AgentBrake-Fusion"',
            "",
            "[model_providers.agentbrake]",
            'name = "AgentBrake-Fusion Gateway"',
            f'base_url = "{gateway["base_url"]}"',
            'wire_api = "responses"',
            'env_key = "AGENTBRAKE_GATEWAY_API_KEY"',
            f'http_headers = {{ X-AgentBrake-Fusion-Run-Id = "{session["run_id"]}" }}',
            "# END AgentBrake-Fusion managed block",
            "",
        ]
    )
    cleaned = _remove_managed_block(original)
    return block + cleaned.lstrip()


def _render_openai_env(config: dict[str, Any], profile: AgentProfile) -> str:
    gateway = config["gateway"]
    session = config["session"]
    return "\n".join(
        [
            "# AgentBrake-Fusion generated agent config snippet.",
            f"OPENAI_BASE_URL={gateway['base_url']}",
            f"{profile.api_key_env}={profile.api_key_value}",
            f"AGENTBRAKE_RUN_ID={session['run_id']}",
            f"AGENTBRAKE_CONVERSATION_ID={session['conversation_id']}",
            "",
        ]
    )


def _remove_managed_block(text: str) -> str:
    start = "# BEGIN AgentBrake-Fusion managed block"
    end = "# END AgentBrake-Fusion managed block"
    if start not in text or end not in text:
        return text
    before, rest = text.split(start, 1)
    _, after = rest.split(end, 1)
    return before.rstrip() + "\n" + after.lstrip()
