from agentbrake.audit import AuditLog
from agentbrake.models import SessionState
from agentbrake.session_state import PersistentSessionStateStore
from agentbrake.state_replay import restore_latest_session_state


def test_restore_latest_session_state_prefers_jsonl_then_audit(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    state_path = tmp_path / "session_state.jsonl"
    audit = AuditLog(audit_path)
    store = PersistentSessionStateStore(state_path, audit_log=audit)
    state = SessionState(
        "state_1",
        "run_restore",
        "task_1",
        secret_taint=True,
        touched_secret_assets=[".env"],
        prior_external_sinks=["https://attacker.example/leak?token=raw"],
        last_decisions=["block"],
    )

    store.append_state_update(state, action_id="act_1", decision_id="dec_1")

    restored = restore_latest_session_state(audit_path, "run_restore", task_id="task_2", state_path=state_path)

    assert restored is not None
    assert restored.run_id == "run_restore"
    assert restored.task_id == "task_2"
    assert restored.secret_taint is True
    assert restored.touched_secret_assets == [".env"]
    assert restored.prior_external_sinks == ["attacker.example"]
    assert restored.state_hash


def test_restore_latest_session_state_uses_audit_when_jsonl_missing(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path)
    store = PersistentSessionStateStore(tmp_path / "state.jsonl", audit_log=audit)
    state = SessionState("state_2", "run_audit", None, package_taint=True, last_decisions=["quarantine"])
    store.append_state_update(state, action_id="act_2", decision_id="dec_2")

    restored = restore_latest_session_state(audit_path, "run_audit", state_path=tmp_path / "missing.jsonl")

    assert restored is not None
    assert restored.package_taint is True
    assert restored.approval_scope["restore_source"] == "audit"
