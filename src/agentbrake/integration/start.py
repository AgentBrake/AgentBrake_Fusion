"""Startup summary for generated AgentBrake-Fusion integrations."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

from .templates import load_config


def build_start_summary(
    repo_root: str | Path,
    *,
    config_path: str | Path | None = None,
    gateway_only: bool = False,
    studio_only: bool = False,
    approval_only: bool = False,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    config = load_config(Path(config_path).resolve() if config_path else repo / ".agentbrake" / "config.yaml")
    services: list[dict[str, Any]] = []
    if not studio_only and not approval_only:
        gateway = config["gateway"]
        services.append(
            {
                "name": "gateway",
                "enabled": True,
                "url": f"http://{gateway['host']}:{gateway['port']}/v1",
                "script": str(repo / ".agentbrake" / "scripts" / "run_gateway.sh"),
            }
        )
    if not gateway_only and not approval_only and config.get("studio", {}).get("enabled"):
        studio = config["studio"]
        services.append(
            {
                "name": "studio",
                "enabled": True,
                "url": f"http://{studio['host']}:{studio['port']}",
                "script": str(repo / ".agentbrake" / "scripts" / "run_studio.sh"),
            }
        )
    if not gateway_only and not studio_only and config.get("approval", {}).get("enabled"):
        approval = config["approval"]
        services.append(
            {
                "name": "approval_api",
                "enabled": True,
                "url": f"http://{approval['host']}:{approval['port']}",
                "script": str(repo / ".agentbrake" / "scripts" / "run_approval.sh"),
            }
        )
    return {
        "ok": True,
        "repo_root": str(repo),
        "mode": config["mode"],
        "agent": config["agent"],
        "services": services,
        "audit_log": config["audit"]["path"],
        "session_state": config["session"].get("state_path", str(repo / ".agentbrake" / "session_state.jsonl")),
        "next_step": f"Set your agent base_url to {config['gateway']['base_url']}",
        "run_id": config["session"]["run_id"],
        "conversation_id": config["session"]["conversation_id"],
    }


def launch_start_services(
    repo_root: str | Path,
    *,
    config_path: str | Path | None = None,
    gateway_only: bool = False,
    studio_only: bool = False,
    approval_only: bool = False,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    config_file = Path(config_path).resolve() if config_path else repo / ".agentbrake" / "config.yaml"
    config = load_config(config_file)
    summary = build_start_summary(
        repo,
        config_path=config_file,
        gateway_only=gateway_only,
        studio_only=studio_only,
        approval_only=approval_only,
    )
    logs_dir = repo / ".agentbrake" / "logs"
    run_dir = repo / ".agentbrake" / "run"
    logs_dir.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    launched: list[dict[str, Any]] = []
    if not studio_only and not approval_only:
        gateway = config["gateway"]
        command = [
            sys.executable,
            "-m",
            "agentbrake.cli",
            "gateway-start",
            "--repo",
            str(repo),
            "--host",
            str(gateway["host"]),
            "--port",
            str(gateway["port"]),
            "--audit",
            str(config["audit"]["path"]),
            "--policy-mode",
            str(config["policy"]["mode"]),
            "--release-mode",
            str(config["policy"].get("release_mode") or "gateway_only"),
        ]
        if gateway.get("upstream_base_url"):
            command.extend(["--upstream-base-url", str(gateway["upstream_base_url"])])
        if config["policy"].get("pack"):
            command.extend(["--policy-config", str(config["policy"]["pack"])])
        launched.append(_launch("gateway", command, repo, logs_dir, run_dir, _service_url("gateway", config)))
    if not gateway_only and not approval_only and config.get("studio", {}).get("enabled"):
        studio = config["studio"]
        command = [
            sys.executable,
            "-m",
            "agentbrake.cli",
            "studio-server",
            "--audit",
            str(config["audit"]["path"]),
            "--approvals",
            str(config["approval"]["store"]),
            "--repo",
            str(repo),
            "--host",
            str(studio["host"]),
            "--port",
            str(studio["port"]),
        ]
        launched.append(_launch("studio", command, repo, logs_dir, run_dir, _service_url("studio", config)))
    if not gateway_only and not studio_only and config.get("approval", {}).get("enabled"):
        approval = config["approval"]
        command = [
            sys.executable,
            "-m",
            "agentbrake.cli",
            "approval-api-start",
            "--store",
            str(approval["store"]),
            "--host",
            str(approval["host"]),
            "--port",
            str(approval["port"]),
        ]
        launched.append(_launch("approval_api", command, repo, logs_dir, run_dir, _service_url("approval_api", config)))
    summary["launched"] = launched
    summary["logs_dir"] = str(logs_dir)
    return summary


def status_services(repo_root: str | Path, *, config_path: str | Path | None = None) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    config_file = Path(config_path).resolve() if config_path else repo / ".agentbrake" / "config.yaml"
    if not config_file.exists():
        return {
            "ok": False,
            "repo_root": str(repo),
            "services": [],
            "repair": "Run: agentbrake connect --repo . --agent custom-openai --mode quick",
        }
    config = load_config(config_file)
    services = []
    for name in _configured_service_names(config):
        pid_record = _read_pid(repo, name)
        host, port = _service_host_port(name, config)
        port_open = _port_open(host, port)
        pid_alive = _pid_alive(int(pid_record.get("pid") or 0)) if pid_record else False
        services.append(
            {
                "name": name,
                "pid": pid_record.get("pid") if pid_record else None,
                "pid_alive": pid_alive,
                "port_open": port_open,
                "status": "running" if pid_alive or port_open else "stopped",
                "url": _service_url(name, config),
                "pid_file": str(_pid_path(repo, name)),
            }
        )
    return {"ok": all(item["status"] == "running" for item in services), "repo_root": str(repo), "services": services}


def stop_services(
    repo_root: str | Path,
    *,
    config_path: str | Path | None = None,
    gateway_only: bool = False,
    studio_only: bool = False,
    approval_only: bool = False,
) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    config_file = Path(config_path).resolve() if config_path else repo / ".agentbrake" / "config.yaml"
    if not config_file.exists():
        return {
            "ok": False,
            "repo_root": str(repo),
            "stopped": [],
            "repair": "Run: agentbrake connect --repo . --agent custom-openai --mode quick",
        }
    config = load_config(config_file)
    names = _configured_service_names(config)
    if gateway_only:
        names = ["gateway"]
    elif studio_only:
        names = ["studio"]
    elif approval_only:
        names = ["approval_api"]
    stopped = []
    for name in names:
        pid_record = _read_pid(repo, name)
        pid = int(pid_record.get("pid") or 0) if pid_record else 0
        ok = False
        detail = "pid file not found"
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                ok = True
                detail = "sent SIGTERM"
            except OSError as exc:
                detail = str(exc)
        _pid_path(repo, name).unlink(missing_ok=True)
        stopped.append({"name": name, "pid": pid or None, "ok": ok, "detail": detail})
    return {"ok": True, "repo_root": str(repo), "stopped": stopped}


def _launch(name: str, command: list[str], repo: Path, logs_dir: Path, run_dir: Path, url: str) -> dict[str, Any]:
    stdout_path = logs_dir / f"{name}.log"
    stderr_path = logs_dir / f"{name}.err.log"
    stdout = stdout_path.open("ab")
    stderr = stderr_path.open("ab")
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        process = subprocess.Popen(command, cwd=repo, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL, creationflags=creationflags)
    finally:
        stdout.close()
        stderr.close()
    result = {
        "name": name,
        "pid": process.pid,
        "command": command,
        "url": url,
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
    }
    _pid_path_from_run_dir(run_dir, name).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def _configured_service_names(config: dict[str, Any]) -> list[str]:
    names = ["gateway"]
    if config.get("studio", {}).get("enabled"):
        names.append("studio")
    if config.get("approval", {}).get("enabled"):
        names.append("approval_api")
    return names


def _service_host_port(name: str, config: dict[str, Any]) -> tuple[str, int]:
    if name == "studio":
        data = config.get("studio", {})
    elif name == "approval_api":
        data = config.get("approval", {})
    else:
        data = config.get("gateway", {})
    return str(data.get("host") or "127.0.0.1"), int(data.get("port") or 0)


def _service_url(name: str, config: dict[str, Any]) -> str:
    host, port = _service_host_port(name, config)
    suffix = "/v1" if name == "gateway" else ""
    return f"http://{host}:{port}{suffix}"


def _pid_path(repo: Path, name: str) -> Path:
    return _pid_path_from_run_dir(repo / ".agentbrake" / "run", name)


def _pid_path_from_run_dir(run_dir: Path, name: str) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir / f"{name}.pid.json"


def _read_pid(repo: Path, name: str) -> dict[str, Any]:
    path = _pid_path(repo, name)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
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
