import json
import socket
import threading
import time
from pathlib import Path
from urllib.request import Request, urlopen

from agentbrake.cli import main
from agentbrake.gateway import serve_gateway, simulate_gateway_request
from agentbrake.gateway.session_identity import resolve_session_identity
from agentbrake.integration import build_start_summary, connect_repo, run_doctor, run_real_agent_smoke_test
from agentbrake.integration.profiles import integration_matrix, profile_for_agent
from agentbrake.integration.start import launch_start_services, status_services, stop_services
from agentbrake.integration.templates import load_config
from agentbrake.studio.server import serve_studio_pro


def test_connect_quick_generates_config_env_and_instructions(tmp_path: Path):
    result = connect_repo(tmp_path, agent="codex", mode="quick")

    assert result.ok
    assert (tmp_path / ".agentbrake" / "config.yaml").exists()
    assert (tmp_path / ".agentbrake" / "agent.env").exists()
    assert (tmp_path / ".agentbrake" / "agent-instructions.md").exists()
    config = load_config(tmp_path / ".agentbrake" / "config.yaml")
    assert config["mode"] == "quick"
    assert config["agent"] == "codex"
    assert config["agent_config"]["wire_api"] == "responses"
    assert config["agent_config"]["smoke_endpoint"] == "/v1/responses"
    assert config["session"]["run_id"].startswith("run_")
    assert not config["shims"]["enabled"]
    env_text = (tmp_path / ".agentbrake" / "agent.env").read_text(encoding="utf-8")
    assert "OPENAI_BASE_URL=" in env_text
    assert "AGENTBRAKE_CONVERSATION_ID=" in env_text


def test_connect_standard_generates_guarded_tool_shims(tmp_path: Path):
    connect_repo(tmp_path, agent="generic", mode="standard")
    config = load_config(tmp_path / ".agentbrake" / "config.yaml")

    assert config["shims"]["enabled"]
    assert (tmp_path / ".agentbrake" / "shims" / "npm").exists()
    assert (tmp_path / ".agentbrake" / "shims" / "curl").exists()
    assert (tmp_path / ".agentbrake" / "scripts" / "run_gateway.sh").exists()


def test_connect_full_generates_studio_approval_and_demo(tmp_path: Path):
    connect_repo(tmp_path, agent="openclaw", mode="full")
    config = load_config(tmp_path / ".agentbrake" / "config.yaml")

    assert config["studio"]["enabled"]
    assert config["approval"]["enabled"]
    assert (tmp_path / ".agentbrake" / "demo" / "normal_request.json").exists()
    assert (tmp_path / ".agentbrake" / "demo" / "attack_request.json").exists()
    summary = build_start_summary(tmp_path)
    assert [service["name"] for service in summary["services"]] == ["gateway", "studio", "approval_api"]


def test_connect_dry_run_does_not_write_files(tmp_path: Path):
    result = connect_repo(tmp_path, agent="generic", mode="full", dry_run=True)

    assert result.dry_run
    assert not (tmp_path / ".agentbrake").exists()
    assert ".agentbrake/config.yaml" in result.skipped


def test_connect_accepts_custom_openai_and_gateway_options(tmp_path: Path):
    connect_repo(
        tmp_path,
        agent="custom-openai-compatible",
        mode="quick",
        upstream_base_url="https://api.example.test/v1",
        policy_pack="policies/policy_pack_gateway.yaml",
    )
    config = load_config(tmp_path / ".agentbrake" / "config.yaml")

    assert config["agent"] == "custom-openai"
    assert config["gateway"]["upstream_base_url"] == "https://api.example.test/v1"
    assert config["policy"]["pack"] == "policies/policy_pack_gateway.yaml"


def test_doctor_and_coverage_pass_for_full_mode(tmp_path: Path):
    connect_repo(tmp_path, agent="generic", mode="full")
    report = run_doctor(tmp_path)

    assert report.ok
    assert report.coverage["ok"]
    assert not report.coverage["missing"]
    assert any(item["name"] == "gateway_port_listening" for item in report.checks)
    assert any("shim path is not first on PATH" in warning for warning in report.warnings)


def test_cli_connect_and_coverage(tmp_path: Path):
    assert main(["connect", "--repo", str(tmp_path), "--agent", "codex", "--mode", "standard"]) == 0
    assert main(["coverage", "--repo", str(tmp_path)]) == 0
    assert main(["start", "--repo", str(tmp_path), "--gateway-only", "--print-only"]) == 0
    assert main(["profiles", "--agent", "codex"]) == 0
    assert main(["integration-matrix"]) == 0


def test_connect_can_apply_and_restore_agent_config_snippet(tmp_path: Path):
    result = connect_repo(tmp_path, agent="generic", mode="quick", apply_config=True)
    assert result.agent_config and result.agent_config["applied"]
    target = Path(result.agent_config["target"])
    assert target.exists()
    assert "OPENAI_BASE_URL=" in target.read_text(encoding="utf-8")

    restored = connect_repo(tmp_path, agent="generic", mode="quick", restore_config=True)
    assert restored.agent_config and restored.agent_config["restored"]
    assert not target.exists()


def test_agent_config_restore_is_agent_scoped(tmp_path: Path):
    result = connect_repo(tmp_path, agent="generic", mode="quick", apply_config=True)
    target = Path(result.agent_config["target"])

    wrong_agent = connect_repo(tmp_path, agent="cline", mode="quick", restore_config=True)
    assert wrong_agent.agent_config and not wrong_agent.agent_config["restored"]
    assert target.exists()

    restored = connect_repo(tmp_path, agent="generic", mode="quick", restore_config=True)
    assert restored.agent_config and restored.agent_config["restored"]
    assert not target.exists()


def test_start_launches_configured_services(tmp_path: Path, monkeypatch):
    connect_repo(tmp_path, agent="generic", mode="full")
    launched_commands = []

    class FakeProcess:
        pid = 4242

    def fake_popen(command, **kwargs):
        launched_commands.append(command)
        return FakeProcess()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    result = launch_start_services(tmp_path)

    assert [item["name"] for item in result["launched"]] == ["gateway", "studio", "approval_api"]
    assert any("gateway-start" in command for command in launched_commands[0])
    assert any("studio-server" in command for command in launched_commands[1])
    assert any("approval-api-start" in command for command in launched_commands[2])


def test_status_and_stop_use_pid_files(tmp_path: Path, monkeypatch):
    connect_repo(tmp_path, agent="generic", mode="full")
    launched_commands = []
    killed = []

    class FakeProcess:
        pid = 4242

    def fake_popen(command, **kwargs):
        launched_commands.append(command)
        return FakeProcess()

    def fake_kill(pid, sig):
        killed.append((pid, sig))

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr("os.kill", fake_kill)
    launch_start_services(tmp_path)

    status = status_services(tmp_path)
    stop = stop_services(tmp_path)

    assert [item["name"] for item in status["services"]] == ["gateway", "studio", "approval_api"]
    assert all(item["pid"] == 4242 for item in status["services"])
    assert [item["name"] for item in stop["stopped"]] == ["gateway", "studio", "approval_api"]
    assert len([item for item in killed if item[1] != 0]) == 3


def test_agent_integration_docs_and_demo_package_exist():
    root = Path(__file__).resolve().parents[1]
    for name in ["custom-openai-compatible", "openclaw", "cline", "openhands", "aider", "codex-cli", "claude-code"]:
        assert (root / "docs" / "integrations" / f"{name}.md").exists()
    demo = root / "examples" / "agent-integration-demo"
    assert (demo / "README.md").exists()
    assert (demo / "start_agentbrake.sh").exists()
    assert (demo / "demo_repo" / "package.json").exists()
    assert (demo / "expected_outputs" / "attack-secret-exfil.md").exists()


def test_doctor_includes_repair_hints_for_missing_config(tmp_path: Path):
    report = run_doctor(tmp_path)

    assert not report.ok
    assert "agentbrake connect" in report.checks[0]["repair"]
    assert report.next_commands


def test_profiles_load_from_external_yaml():
    codex = profile_for_agent("codex")
    assert codex.wire_api == "responses"
    assert codex.config_apply == "native"
    assert codex.real_agent_command == ("codex", "exec")
    matrix = integration_matrix()
    assert any(row["agent"] == "codex" and row["maturity"] == "native" for row in matrix)


def test_real_agent_smoke_reports_unsupported_profile(tmp_path: Path):
    connect_repo(tmp_path, agent="generic", mode="quick")
    config = load_config(tmp_path / ".agentbrake" / "config.yaml")
    result = run_real_agent_smoke_test(config, profile_for_agent("generic"))
    assert not result["ok"]
    assert result["detail"] == "profile has no real_agent_command"


def test_real_agent_smoke_refuses_when_gateway_is_not_running(tmp_path: Path):
    connect_repo(tmp_path, agent="codex", mode="quick")
    config = load_config(tmp_path / ".agentbrake" / "config.yaml")
    result = run_real_agent_smoke_test(config, profile_for_agent("codex"), command=["python", "-c", "print('OK')"], timeout=1)

    assert not result["ok"]
    assert "Gateway is not listening" in result["detail"]


def test_status_and_stop_include_repair_when_not_connected(tmp_path: Path):
    status = status_services(tmp_path)
    stop = stop_services(tmp_path)

    assert not status["ok"]
    assert "agentbrake connect" in status["repair"]
    assert not stop["ok"]
    assert "agentbrake connect" in stop["repair"]


def test_doctor_probes_live_gateway(tmp_path: Path):
    connect_repo(tmp_path, agent="generic", mode="quick")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config = load_config(tmp_path / ".agentbrake" / "config.yaml")
    config["gateway"]["port"] = port
    (tmp_path / ".agentbrake" / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
    thread = threading.Thread(
        target=serve_gateway,
        kwargs={"repo_root": tmp_path, "host": "127.0.0.1", "port": port, "audit_path": tmp_path / ".agentbrake" / "gateway_audit.jsonl"},
        daemon=True,
    )
    thread.start()
    time.sleep(0.25)

    report = run_doctor(tmp_path)

    assert any(item["name"] == "gateway_chat_smoke" and item["ok"] for item in report.checks)


def test_doctor_uses_agent_specific_responses_smoke(tmp_path: Path):
    connect_repo(tmp_path, agent="codex", mode="quick")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config = load_config(tmp_path / ".agentbrake" / "config.yaml")
    config["gateway"]["port"] = port
    (tmp_path / ".agentbrake" / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
    thread = threading.Thread(
        target=serve_gateway,
        kwargs={"repo_root": tmp_path, "host": "127.0.0.1", "port": port, "audit_path": tmp_path / ".agentbrake" / "gateway_audit.jsonl"},
        daemon=True,
    )
    thread.start()
    time.sleep(0.25)

    report = run_doctor(tmp_path, agent="codex")

    assert any(item["name"] == "gateway_responses_smoke" and item["ok"] for item in report.checks)
    assert main(["smoke-test", "--repo", str(tmp_path), "--agent", "codex"]) == 0


def test_studio_exposes_coverage_endpoint(tmp_path: Path):
    connect_repo(tmp_path, agent="generic", mode="full")
    simulate_gateway_request(
        tmp_path,
        {"model": "agentbrake/local-heuristic", "messages": [{"role": "user", "content": "fix login"}]},
        audit_path=tmp_path / ".agentbrake" / "gateway_audit.jsonl",
    )
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    thread = threading.Thread(
        target=serve_studio_pro,
        kwargs={
            "audit_path": tmp_path / ".agentbrake" / "gateway_audit.jsonl",
            "approvals_path": tmp_path / ".agentbrake" / "gateway_approvals.jsonl",
            "repo_root": tmp_path,
            "host": "127.0.0.1",
            "port": port,
        },
        daemon=True,
    )
    thread.start()
    time.sleep(0.25)
    req = Request(f"http://127.0.0.1:{port}/api/coverage", headers={"Authorization": "Bearer agentbrake-fusion-local"})

    with urlopen(req, timeout=5) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    assert payload["mode"] == "full"
    assert any(row["capability"] == "model_response" for row in payload["matrix"])


def test_session_identity_derives_client_and_first_user_message_hash(tmp_path: Path):
    first = resolve_session_identity(
        request={"metadata": {"client_id": "agent-a"}, "messages": [{"role": "user", "content": "fix login"}]},
        repo_root=tmp_path,
    )
    second = resolve_session_identity(
        request={"metadata": {"client_id": "agent-a"}, "messages": [{"role": "user", "content": "fix login"}]},
        repo_root=tmp_path,
    )
    different = resolve_session_identity(
        request={"metadata": {"client_id": "agent-a"}, "messages": [{"role": "user", "content": "fix billing"}]},
        repo_root=tmp_path,
    )

    assert first.run_id == second.run_id
    assert first.run_id != different.run_id
    assert first.source == "derived.client_message"
