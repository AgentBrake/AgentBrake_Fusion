"""Implementation of ``agentbrake doctor``."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .coverage import build_coverage_report, filesystem_checks
from .profiles import AgentProfile, profile_for_agent
from .templates import load_config


@dataclass(slots=True)
class DoctorReport:
    ok: bool
    config_path: str
    checks: list[dict[str, Any]]
    coverage: dict[str, Any]
    warnings: list[str]
    next_commands: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "config_path": self.config_path,
            "checks": self.checks,
            "coverage": self.coverage,
            "warnings": self.warnings,
            "next_commands": self.next_commands,
        }


def run_doctor(repo_root: str | Path, *, config_path: str | Path | None = None, agent: str | None = None) -> DoctorReport:
    repo = Path(repo_root).resolve()
    config_file = Path(config_path).resolve() if config_path else repo / ".agentbrake" / "config.yaml"
    checks: list[dict[str, Any]] = []
    warnings: list[str] = []
    if not config_file.exists():
        return DoctorReport(
            False,
            str(config_file),
            [
                {
                    "name": "config",
                    "ok": False,
                    "detail": "missing config.yaml",
                    "repair": "Run: agentbrake connect --repo . --agent custom-openai --mode quick",
                }
            ],
            {},
            warnings,
            ["agentbrake connect --repo . --agent custom-openai --mode quick"],
        )
    config = load_config(config_file)
    configured_agent = str(agent or config.get("agent") or "generic")
    agent_profile = profile_for_agent(configured_agent)
    _check(checks, "config", True, str(config_file))
    _check(checks, "agent_profile", True, f"{agent_profile.agent}:{agent_profile.wire_api}")
    agent_config = config.get("agent_config", {})
    _check(checks, "agent_protocol_declared", agent_config.get("wire_api") == agent_profile.wire_api, agent_profile.wire_api)
    _check(
        checks,
        "agent_authorization_declared",
        bool(agent_config.get("api_key_env") or agent_config.get("api_key")),
        "agent profile must declare api_key_env or api_key",
    )
    audit_path = Path(str(config.get("audit", {}).get("path", repo / ".agentbrake" / "gateway_audit.jsonl")))
    _check(checks, "audit_dir_writable", _is_writable(audit_path.parent), str(audit_path.parent))
    session_path = Path(str(config.get("session", {}).get("state_path", repo / ".agentbrake" / "session_state.jsonl")))
    _check(checks, "session_state_writable", _is_writable(session_path.parent), str(session_path))
    session = config.get("session", {})
    has_stable_identity = bool(session.get("run_id") and session.get("conversation_id"))
    _check(checks, "stable_run_identity", has_stable_identity, "run_id and conversation_id are required")
    if not str(session.get("run_id") or "").startswith("run_"):
        warnings.append("session run_id does not use the expected run_ prefix")
    shims = config.get("shims", {})
    if shims.get("enabled"):
        shim_path = Path(str(shims.get("path", "")))
        _check(checks, "shims_exist", shim_path.exists(), str(shim_path))
        _check(checks, "shims_on_path", _path_contains(shim_path), str(shim_path))
        if not _path_first(shim_path):
            warnings.append(f"shim path is not first on PATH: {shim_path}")
        elif not _path_contains(shim_path):
            warnings.append(f"shim path is not on PATH: {shim_path}")
    gateway = config.get("gateway", {})
    _check(checks, "gateway_configured", bool(gateway.get("enabled") and gateway.get("port")), str(gateway))
    gateway_host = str(gateway.get("host") or "127.0.0.1")
    gateway_port = int(gateway.get("port") or 0)
    gateway_listening = _port_open(gateway_host, gateway_port)
    _check(checks, "gateway_port_listening", gateway_listening, "warning-only")
    if gateway_listening:
        smoke = run_smoke_test(config, agent_profile)
        _check(checks, f"gateway_{agent_profile.wire_api}_smoke", bool(smoke.get("ok")), str(smoke))
    if gateway.get("upstream_base_url") and not os.getenv("OPENAI_API_KEY"):
        warnings.append("OPENAI_API_KEY is not set; upstream forwarding may fail")
    policy_pack = str(config.get("policy", {}).get("pack") or "")
    if policy_pack:
        _check(checks, "policy_pack_exists", Path(policy_pack).exists(), policy_pack)
    studio = config.get("studio", {})
    if studio.get("enabled"):
        studio_host = str(studio.get("host") or "127.0.0.1")
        studio_port = int(studio.get("port") or 0)
        studio_listening = _port_open(studio_host, studio_port)
        _check(checks, "studio_port_listening", studio_listening, "warning-only")
        if studio_listening:
            _check(checks, "studio_health", _probe_studio(studio_host, studio_port), "/api/health")
    coverage = build_coverage_report(config, filesystem_checks(config))
    hard_checks = [
        item
        for item in checks
        if item["name"]
        not in {"gateway_port_listening", "gateway_chat_completions", "studio_port_listening", "studio_health", "shims_on_path"}
    ]
    ok = all(item["ok"] for item in hard_checks) and bool(coverage.get("ok"))
    return DoctorReport(ok, str(config_file), checks, coverage, warnings, _next_commands(config, agent_profile, checks))


def _check(checks: list[dict[str, Any]], name: str, ok: bool, detail: str) -> None:
    item = {"name": name, "ok": bool(ok), "detail": detail}
    repair = _repair_hint(name, ok, detail)
    if repair:
        item["repair"] = repair
    checks.append(item)


def _repair_hint(name: str, ok: bool, detail: str) -> str:
    if ok:
        return ""
    hints = {
        "config": "Run: agentbrake connect --repo . --agent custom-openai --mode quick",
        "audit_dir_writable": f"Create or fix permissions for: {detail}",
        "session_state_writable": f"Create or fix permissions for: {detail}",
        "stable_run_identity": "Regenerate config: agentbrake connect --repo . --mode quick --force",
        "agent_protocol_declared": "Regenerate config for this agent: agentbrake connect --repo . --agent <agent> --force",
        "agent_authorization_declared": "Regenerate config: agentbrake connect --repo . --force",
        "shims_exist": "Regenerate shims: agentbrake connect --repo . --mode standard --force",
        "shims_on_path": 'Put shims first: export PATH="$(pwd)/.agentbrake/shims:$PATH"',
        "gateway_configured": "Regenerate config: agentbrake connect --repo . --mode quick --force",
        "gateway_port_listening": "Start Gateway: agentbrake start --repo . --gateway-only",
        "gateway_chat_completions": "Check logs in .agentbrake/logs/gateway.err.log and verify Authorization uses Bearer agentbrake-fusion-local.",
        "gateway_chat_smoke": "Start Gateway and verify /v1/chat/completions accepts Authorization: Bearer agentbrake-fusion-local.",
        "gateway_responses_smoke": "Start Gateway and verify /v1/responses accepts Authorization: Bearer agentbrake-fusion-local.",
        "policy_pack_exists": f"Fix --policy-pack path or remove it from config: {detail}",
        "studio_port_listening": "Start Studio: agentbrake start --repo .",
        "studio_health": "Check logs in .agentbrake/logs/studio.err.log and verify Studio bearer token.",
    }
    return hints.get(name, "Inspect this check and rerun: agentbrake doctor --repo .")


def _is_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".agentbrake_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def _path_contains(path: Path) -> bool:
    wanted = str(path.resolve()).lower()
    return any(str(Path(part).resolve()).lower() == wanted for part in os.environ.get("PATH", "").split(os.pathsep) if part)


def _path_first(path: Path) -> bool:
    parts = [part for part in os.environ.get("PATH", "").split(os.pathsep) if part]
    if not parts:
        return False
    try:
        return str(Path(parts[0]).resolve()).lower() == str(path.resolve()).lower()
    except OSError:
        return False


def _port_open(host: str, port: int) -> bool:
    if port <= 0:
        return False
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except OSError:
        return False


def run_smoke_test(config: dict[str, Any], agent_profile: AgentProfile | None = None) -> dict[str, Any]:
    profile = agent_profile or profile_for_agent(str(config.get("agent") or "generic"))
    gateway = config.get("gateway", {})
    session = config.get("session", {})
    host = str(gateway.get("host") or "127.0.0.1")
    port = int(gateway.get("port") or 0)
    endpoint = profile.smoke_endpoint
    payload = _smoke_payload(profile, session)
    try:
        request = Request(
            f"http://{host}:{port}{endpoint}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {profile.api_key_value}"},
            method="POST",
        )
        with urlopen(request, timeout=2) as response:
            ok = response.status == 200 and bool(response.headers.get("X-AgentBrake-Fusion-Run-Id"))
            return {"ok": ok, "endpoint": endpoint, "status": response.status, "run_id_header": response.headers.get("X-AgentBrake-Fusion-Run-Id")}
    except HTTPError as exc:
        return {"ok": False, "endpoint": endpoint, "status": exc.code, "error": str(exc)}
    except (URLError, OSError) as exc:
        return {"ok": False, "endpoint": endpoint, "status": 0, "error": str(exc)}


def run_real_agent_smoke_test(
    config: dict[str, Any],
    agent_profile: AgentProfile | None = None,
    *,
    command: list[str] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    profile = agent_profile or profile_for_agent(str(config.get("agent") or "generic"))
    template = command or list(profile.real_agent_command)
    if not template:
        return {"ok": False, "agent": profile.agent, "available": False, "detail": "profile has no real_agent_command"}
    gateway = config.get("gateway", {})
    host = str(gateway.get("host") or "127.0.0.1")
    port = int(gateway.get("port") or 0)
    if not _port_open(host, port):
        return {
            "ok": False,
            "agent": profile.agent,
            "available": False,
            "detail": f"AgentBrake-Fusion Gateway is not listening at {host}:{port}; run agentbrake start --repo . --gateway-only first.",
        }
    configured = _real_agent_configured_for_gateway(config, profile)
    if not configured["ok"]:
        return {"ok": False, "agent": profile.agent, "available": False, **configured}
    executable = template[0]
    if shutil.which(executable) is None:
        return {"ok": False, "agent": profile.agent, "available": False, "detail": f"command not found: {executable}"}
    if profile.agent == "codex":
        cmd = [
            *template,
            "--cd",
            str(config.get("repo_root") or "."),
            "--sandbox",
            "read-only",
            "--skip-git-repo-check",
            "--ephemeral",
            profile.smoke_prompt,
        ]
    else:
        cmd = [*template, profile.smoke_prompt]
    env = os.environ.copy()
    env[profile.api_key_env] = profile.api_key_value
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(config.get("repo_root") or "."),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "agent": profile.agent, "available": True, "command": cmd, "detail": str(exc)}
    output = f"{completed.stdout}\n{completed.stderr}"
    return {
        "ok": completed.returncode == 0 and "OK" in output,
        "agent": profile.agent,
        "available": True,
        "command": cmd,
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-800:],
        "stderr_tail": completed.stderr[-800:],
    }


def _real_agent_configured_for_gateway(config: dict[str, Any], profile: AgentProfile) -> dict[str, Any]:
    if profile.agent != "codex":
        return {"ok": True}
    config_path = Path.home() / ".codex" / "config.toml"
    if not config_path.exists():
        return {"ok": False, "detail": f"Codex config not found: {config_path}"}
    text = config_path.read_text(encoding="utf-8", errors="replace")
    gateway_url = str(config.get("gateway", {}).get("base_url") or "")
    markers = [
        "# BEGIN AgentBrake-Fusion managed block",
        'model_provider = "AgentBrake-Fusion"',
        "[model_providers.agentbrake]",
        gateway_url,
    ]
    if all(marker in text for marker in markers if marker):
        return {"ok": True}
    return {
        "ok": False,
        "detail": "Codex is not configured to use this AgentBrake-Fusion Gateway; run agentbrake connect --repo . --agent codex --apply-agent-config first.",
    }


def _smoke_payload(profile: AgentProfile, session: dict[str, Any]) -> dict[str, Any]:
    metadata = {
        "agentbrake_run_id": session.get("run_id"),
        "conversation_id": session.get("conversation_id"),
        "client_id": f"AgentBrake-Fusion-doctor-{profile.agent}",
    }
    if profile.wire_api == "responses":
        return {
            "model": profile.model,
            "input": profile.smoke_prompt,
            "metadata": metadata,
        }
    return {
        "model": profile.model,
        "messages": [{"role": "user", "content": profile.smoke_prompt}],
        "metadata": metadata,
    }


def _probe_studio(host: str, port: int) -> bool:
    try:
        request = Request(
            f"http://{host}:{port}/api/health",
            headers={"Authorization": "Bearer agentbrake-fusion-local"},
            method="GET",
        )
        with urlopen(request, timeout=2) as response:
            return response.status == 200
    except (HTTPError, URLError, OSError):
        return False


def _next_commands(config: dict[str, Any], profile: AgentProfile, checks: list[dict[str, Any]]) -> list[str]:
    names = {item["name"] for item in checks if not item["ok"]}
    commands: list[str] = []
    if "agent_protocol_declared" in names or "agent_authorization_declared" in names or "stable_run_identity" in names:
        commands.append(f"agentbrake connect --repo . --agent {profile.agent} --mode {config.get('mode', 'quick')} --force")
    if "gateway_port_listening" in names:
        commands.append("agentbrake start --repo . --gateway-only")
    if "studio_port_listening" in names and config.get("studio", {}).get("enabled"):
        commands.append("agentbrake start --repo .")
    if "shims_on_path" in names:
        commands.append('export PATH="$(pwd)/.agentbrake/shims:$PATH"')
    if any(name.endswith("_smoke") for name in names):
        commands.append(f"AgentBrake-Fusion smoke-test --repo . --agent {profile.agent}")
    return list(dict.fromkeys(commands))
