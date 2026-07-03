from __future__ import annotations

from agentbrake.audit import AuditLog
from agentbrake.control_plane import AgentBrakeControlPlane
from agentbrake.eval.fast_mode import load_eval_fast_mode_config
from agentbrake.models import ActionIR


def test_fast_mode_config_defaults_from_env(monkeypatch):
    monkeypatch.setenv("AGENTBRAKE_EVAL_FAST_MODE", "1")
    cfg = load_eval_fast_mode_config()
    assert cfg.enabled is True
    assert cfg.disable_preflight is True
    assert cfg.policy_trace_mode == "summary"


def test_control_plane_emits_performance_trace_and_skips_preflight_in_fast_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBRAKE_EVAL_FAST_MODE", "1")
    monkeypatch.setenv("AGENTBRAKE_DISABLE_PREFLIGHT", "1")
    repo = tmp_path / "repo"
    repo.mkdir()
    cp = AgentBrakeControlPlane(repo, audit_path=tmp_path / "audit.jsonl")
    cp.build_contract("fix login")
    action = ActionIR(
        "act_fast_1",
        "cat README.md",
        "Bash",
        str(repo),
        "read_project_file",
        "low",
        ["read_only"],
        ["README.md"],
        [],
    )
    _action, decision = cp.guard_action_ir(action, run_preflight=True)
    assert decision.decision == "allow"
    events = AuditLog(tmp_path / "audit.jsonl").read_events()
    assert any(event["event_type"] == "performance_trace" for event in events)
    assert not any(event["event_type"] == "exec_trace" for event in events)
