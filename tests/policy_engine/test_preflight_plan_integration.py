from agentbrake.control_plane import AgentBrakeControlPlane


def test_control_plane_uses_msj_preflight_plan_for_tests(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "package.json").write_text('{"scripts":{"test":"echo ok"}}', encoding="utf-8")
    cp = AgentBrakeControlPlane(tmp_path, audit_path=tmp_path / "audit.jsonl")
    cp.build_contract("fix login button and run tests")

    _action, decision = cp.guard_action("npm test")
    events = cp.audit.read_events()

    assert decision.decision == "allow_in_sandbox"
    exec_events = [e for e in events if e["event_type"] == "exec_trace"]
    assert exec_events
    assert exec_events[-1]["payload"]["metadata"]["evidence_mode"] == "summary"
    assert any(e["event_type"] == "policy_fact_set" for e in events)
    assert any(e["event_type"] == "policy_eval_trace" for e in events)
