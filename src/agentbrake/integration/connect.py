"""Implementation of ``agentbrake connect``."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .agent_config import apply_agent_config, restore_agent_config
from .doctor import run_smoke_test
from .profiles import SHIM_COMMANDS, IntegrationProfile, make_profile
from .session_bootstrap import default_conversation_id, default_run_id
from .templates import (
    dump_config,
    generated_paths,
    render_agent_env,
    render_agent_instructions,
    render_approval_script,
    render_connect_readme,
    render_demo_request,
    render_gateway_script,
    render_shim,
    render_start_all_script,
    render_studio_script,
)


@dataclass(slots=True)
class ConnectResult:
    repo_root: str
    agent: str
    mode: str
    config_path: str
    written: list[str]
    skipped: list[str]
    dry_run: bool = False
    smoke_test: dict[str, Any] | None = None
    agent_config: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "repo_root": self.repo_root,
            "agent": self.agent,
            "mode": self.mode,
            "config_path": self.config_path,
            "written": self.written,
            "skipped": self.skipped,
            "dry_run": self.dry_run,
            "smoke_test": self.smoke_test,
            "agent_config": self.agent_config,
        }


def connect_repo(
    repo_root: str | Path,
    *,
    agent: str = "generic",
    mode: str = "quick",
    force: bool = False,
    dry_run: bool = False,
    gateway_host: str = "127.0.0.1",
    gateway_port: int = 8765,
    studio_port: int = 8780,
    approval_port: int = 8776,
    upstream_base_url: str | None = None,
    policy_pack: str | Path | None = None,
    smoke_test: bool = False,
    apply_config: bool = False,
    restore_config: bool = False,
) -> ConnectResult:
    repo = Path(repo_root).resolve()
    if not repo.exists() or not repo.is_dir():
        raise FileNotFoundError(f"repo root does not exist: {repo}")
    profile = make_profile(agent, mode)
    config = _build_config(
        repo,
        profile,
        gateway_host=gateway_host,
        gateway_port=gateway_port,
        studio_port=studio_port,
        approval_port=approval_port,
        upstream_base_url=upstream_base_url,
        policy_pack=policy_pack,
    )
    base = repo / ".agentbrake"
    config_path = base / "config.yaml"
    planned = generated_paths(profile)
    if restore_config:
        restored = restore_agent_config(repo, profile.agent_profile)
        return ConnectResult(
            str(repo),
            profile.agent,
            profile.mode,
            str(config_path),
            [],
            [],
            agent_config=restored.to_dict(),
        )
    if dry_run:
        return ConnectResult(str(repo), profile.agent, profile.mode, str(config_path), [], planned, dry_run=True)

    written: list[str] = []
    skipped: list[str] = []
    for directory in [base, base / "scripts", base / "logs"]:
        directory.mkdir(parents=True, exist_ok=True)
    if profile.shims:
        (base / "shims").mkdir(parents=True, exist_ok=True)
    if profile.demo_package:
        (base / "demo").mkdir(parents=True, exist_ok=True)

    _write(base / "config.yaml", dump_config(config), force, written, skipped)
    _write(base / "agent.env", render_agent_env(config), force, written, skipped)
    _write(base / "agent-instructions.md", render_agent_instructions(config), force, written, skipped)
    _write(base / "README_CONNECT.md", render_connect_readme(config), force, written, skipped)
    _write(base / "scripts" / "run_gateway.sh", render_gateway_script(config, ".sh"), force, written, skipped, executable=True)
    _write(base / "scripts" / "run_gateway.ps1", render_gateway_script(config, ".ps1"), force, written, skipped)
    _write(base / "scripts" / "start_all.sh", render_start_all_script(config, ".sh"), force, written, skipped, executable=True)
    _write(base / "scripts" / "start_all.ps1", render_start_all_script(config, ".ps1"), force, written, skipped)

    if profile.studio:
        _write(base / "scripts" / "run_studio.sh", render_studio_script(config, ".sh"), force, written, skipped, executable=True)
        _write(base / "scripts" / "run_studio.ps1", render_studio_script(config, ".ps1"), force, written, skipped)
    if profile.approval_api:
        _write(base / "scripts" / "run_approval.sh", render_approval_script(config, ".sh"), force, written, skipped, executable=True)
        _write(base / "scripts" / "run_approval.ps1", render_approval_script(config, ".ps1"), force, written, skipped)
    if profile.shims:
        for command in SHIM_COMMANDS:
            _write(base / "shims" / command, render_shim(command, config, ""), force, written, skipped, executable=True)
            if os.name == "nt":
                _write(base / "shims" / f"{command}.cmd", render_shim(command, config, ".cmd"), force, written, skipped)
    if profile.demo_package:
        _write(base / "demo" / "normal_request.json", render_demo_request(config), force, written, skipped)
        _write(base / "demo" / "attack_request.json", render_demo_request(config, attack=True), force, written, skipped)

    for path in [base / "gateway_audit.jsonl", base / "gateway_approvals.jsonl", base / "session_state.jsonl"]:
        path.touch(exist_ok=True)
    agent_config_result = apply_agent_config(repo, config, profile.agent_profile, force=force).to_dict() if apply_config else None
    smoke_result = run_smoke_test(config, profile.agent_profile) if smoke_test else None
    return ConnectResult(
        str(repo),
        profile.agent,
        profile.mode,
        str(config_path),
        written,
        skipped,
        smoke_test=smoke_result,
        agent_config=agent_config_result,
    )


def _build_config(
    repo: Path,
    profile: IntegrationProfile,
    *,
    gateway_host: str,
    gateway_port: int,
    studio_port: int,
    approval_port: int,
    upstream_base_url: str | None,
    policy_pack: str | Path | None,
) -> dict[str, Any]:
    conversation_id = default_conversation_id(repo, profile.agent)
    run_id = default_run_id(repo, profile.agent, conversation_id)
    base = repo / ".agentbrake"
    state_path = base / "session_state.jsonl"
    return {
        "version": 1,
        "repo_root": str(repo),
        "agent": profile.agent,
        "agent_config": {
            "type": profile.agent,
            "display_name": profile.agent_profile.display_name,
            "protocol": profile.agent_profile.protocol,
            "wire_api": profile.agent_profile.wire_api,
            "base_url": f"http://{gateway_host}:{gateway_port}/v1",
            "api_key": profile.agent_profile.api_key_value,
            "api_key_env": profile.agent_profile.api_key_env,
            "requires_authorization": profile.agent_profile.requires_authorization,
            "supports_base_url": profile.agent_profile.supports_base_url,
            "supports_headers": profile.agent_profile.supports_headers,
            "stable_identity_channels": list(profile.agent_profile.stable_identity_channels),
            "config_files": list(profile.agent_profile.config_files),
            "smoke_endpoint": profile.agent_profile.smoke_endpoint,
        },
        "mode": profile.mode,
        "gateway": {
            "enabled": True,
            "host": gateway_host,
            "port": gateway_port,
            "base_url": f"http://{gateway_host}:{gateway_port}/v1",
            "upstream_base_url": upstream_base_url or "",
        },
        "policy": {
            "mode": "enforce",
            "pack": str(policy_pack) if policy_pack else "",
            "release_mode": "gateway_plus_guarded_tools" if profile.guarded_tools else "gateway_only",
        },
        "audit": {
            "path": str(base / "gateway_audit.jsonl"),
            "exec_guard_path": str(base / "exec_guard_audit.jsonl"),
        },
        "session": {
            "run_id": run_id,
            "conversation_id": conversation_id,
            "state_path": str(state_path),
            "require_stable_run_id": True,
            "required_metadata": ["metadata.agentbrake_run_id", "metadata.conversation_id"],
        },
        "shims": {"enabled": profile.shims, "path": str(base / "shims"), "commands": list(SHIM_COMMANDS) if profile.shims else []},
        "studio": {"enabled": profile.studio, "host": gateway_host, "port": studio_port},
        "approval": {
            "enabled": profile.approval_api,
            "host": gateway_host,
            "port": approval_port,
            "store": str(base / "gateway_approvals.jsonl"),
        },
        "demo": {
            "enabled": profile.demo_package,
            "normal_request": str(base / "demo" / "normal_request.json") if profile.demo_package else "",
            "attack_request": str(base / "demo" / "attack_request.json") if profile.demo_package else "",
        },
        "capabilities": profile.expected_capabilities,
    }


def _write(path: Path, content: str, force: bool, written: list[str], skipped: list[str], *, executable: bool = False) -> None:
    if path.exists() and not force:
        skipped.append(str(path))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="" if path.suffix == ".cmd" else None)
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    written.append(str(path))
