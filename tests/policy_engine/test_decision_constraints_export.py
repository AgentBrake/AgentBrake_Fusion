from agentbrake.action_parser import ActionParser
from agentbrake.asset import AssetScanner
from agentbrake.context import ContextProvenance
from agentbrake.contract import TaskContractBuilder
from agentbrake.policy_engine.engine import PolicyEngine


def test_policy_decision_exports_constraint_metadata_for_block(tmp_path):
    (tmp_path / ".env").write_text("TOKEN=x", encoding="utf-8")
    contract = TaskContractBuilder().build("inspect")
    action = ActionParser().parse("cat .env", cwd=tmp_path)
    graph = AssetScanner(tmp_path, env={}).scan()

    decision = PolicyEngine().decide(contract, action, graph, ContextProvenance().graph)

    constraints = decision.metadata["decision_constraints"]
    assert decision.decision == "block"
    assert constraints["execution_env"] == "none"
    assert constraints["network_scope"] == "deny"
    assert "constraint_summary" in decision.metadata


def test_policy_decision_exports_constraint_metadata_for_sandbox(tmp_path):
    contract = TaskContractBuilder().build("run tests")
    action = ActionParser().parse("npm test", cwd=tmp_path)
    graph = AssetScanner(tmp_path, env={}).scan()

    decision = PolicyEngine().decide(contract, action, graph, ContextProvenance().graph)

    constraints = decision.metadata["decision_constraints"]
    assert decision.decision == "allow_in_sandbox"
    assert constraints["execution_env"] == "sandbox"
