from agentbrake.action_parser import ActionParser
from agentbrake.asset import AssetScanner
from agentbrake.context import ContextProvenance
from agentbrake.contract import TaskContractBuilder
from agentbrake.models import PolicyDecision
from agentbrake.policy import PolicyEngine
from agentbrake.policy_config import ConfigurablePolicyOverrides
from agentbrake.policy_engine import MSJEngine, PolicyGraphEngine


def test_outer_msj_engine_records_braketrace(tmp_path):
    (tmp_path / ".env").write_text("TOKEN=x", encoding="utf-8")
    contract = TaskContractBuilder().build("fix login")
    graph = AssetScanner(tmp_path, env={}).scan()
    action = ActionParser().parse("tail .env", cwd=tmp_path)
    action.semantic_action = "read_project_file"
    engine = PolicyEngine(mode="legacy")

    decision = engine.decide(contract, action, graph, ContextProvenance().graph)
    events = engine.consume_eval_events()

    assert decision.decision == "block"
    assert decision.policy_version == "agentbrake-fusion-msj-v0.4"
    assert decision.metadata["decision_model"] == "AgentBrake-Fusion/MSJ Engine"
    assert events
    assert events[-1]["engine_mode"] == "msj-enforce"
    assert events[-1]["trace_type"] == "BrakeTrace"
    assert events[-1]["decision_model"] == "AgentBrake-Fusion/MSJ Engine"
    assert events[-1]["invariant_hits"] == ["INV-SECRET-001"]


def test_policygraph_engine_alias_points_to_msj_engine():
    assert PolicyGraphEngine is MSJEngine


def test_invariant_decision_cannot_be_downgraded_by_admin_signed_override():
    decision = PolicyDecision(
        "dec_1",
        "act_1",
        "block",
        100,
        ["secret_asset_touched"],
        ["block"],
        "blocked",
        matched_rules=[{"rule_id": "INV-SECRET-001", "invariant": True}],
        rule_trace=[{"invariant_hits": ["INV-SECRET-001"]}],
    )
    overrides = ConfigurablePolicyOverrides(
        [
            {
                "name": "try_allow_secret",
                "match": {"decision": "block"},
                "decision": "allow",
                "unsafe_override": True,
                "admin_signed": True,
            }
        ]
    )

    updated = overrides.apply(ActionParser().parse("cat .env"), decision)

    assert updated.decision == "block"
    assert "invariant_policy_downgrade_rejected" in updated.reason_codes
