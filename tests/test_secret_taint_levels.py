from agentbrake.action_parser import ActionParser
from agentbrake.models import ExecTrace, PolicyDecision, SessionState
from agentbrake.session_state import PersistentSessionStateStore, SessionStateStore


def _decision(value: str) -> PolicyDecision:
    return PolicyDecision(
        decision_id=f"dec_{value}",
        action_id="act_test",
        decision=value,  # type: ignore[arg-type]
        risk_score=100,
        reason_codes=[],
        required_controls=[],
        explanation="test",
    )


def test_blocked_secret_read_is_attempted_not_confirmed(tmp_path):
    action = ActionParser().parse("cat .env", cwd=tmp_path)
    state = SessionStateStore().update(action, _decision("block"), run_id="run_attempted", task_id="task_1")

    assert state.attempted_secret_taint is True
    assert state.confirmed_secret_taint is False
    assert state.secret_taint is True
    assert state.taint_confidence == "attempted"


def test_sandbox_trace_secret_read_is_confirmed(tmp_path):
    action = ActionParser().parse("cat .env", cwd=tmp_path)
    trace = ExecTrace(
        exec_trace_id="trace_secret",
        action_id=action.action_id,
        command=action.raw_action,
        sandbox_profile="dry-run",
        files_read=[".env"],
        risk_observed=["secret_access"],
    )

    state = SessionStateStore().update(action, _decision("allow_in_sandbox"), trace, run_id="run_confirmed", task_id="task_1")

    assert state.confirmed_secret_taint is True
    assert state.attempted_secret_taint is False
    assert state.taint_confidence == "confirmed"


def test_legacy_secret_taint_migrates_to_confirmed(tmp_path):
    store = PersistentSessionStateStore(tmp_path / "state.jsonl")
    legacy = {
        "session_state_id": "state_legacy",
        "run_id": "run_legacy",
        "task_id": "task_1",
        "secret_taint": True,
        "touched_secret_assets": [".env"],
    }
    record = {"run_id": "run_legacy", "task_id": "task_1", "state": legacy}
    store.path.write_text(__import__("json").dumps(record) + "\n", encoding="utf-8")

    restored = store.restore_latest_state("run_legacy")

    assert restored is not None
    assert restored.confirmed_secret_taint is True
    assert restored.confirmed_secret_assets == [".env"]


def test_payload_contains_attempted_and_confirmed_fields(tmp_path):
    store = PersistentSessionStateStore(tmp_path / "state.jsonl")
    state = SessionState("state_payload", "run_payload", "task_1", attempted_secret_taint=True, attempted_secret_assets=[".env"])

    record = store.append_state_update(state, action_id="act_1", decision_id="dec_1")

    payload = record["state"]
    assert payload["attempted_secret_taint"] is True
    assert payload["confirmed_secret_taint"] is False
    assert payload["taint_confidence"] == "attempted"
