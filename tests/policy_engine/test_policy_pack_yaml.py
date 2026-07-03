from pathlib import Path

from agentbrake.policy_engine.engine import MSJEngine
from agentbrake.policy_runtime.policy_pack import load_policy_pack, validate_policy_pack


def test_core_general_agent_yaml_is_loaded_as_msj_rules():
    engine = MSJEngine()
    ids = {rule.rule_id for rule in engine.rule_index.rules}

    assert "RS-SECRET-001" in ids
    assert "RS-SC-001" in ids
    assert "RS-SANDBOX-001" in ids


def test_core_general_agent_yaml_validates():
    path = Path("src/agentbrake/policy_engine/policies/core_general_agent.yaml")
    data = load_policy_pack(path)
    assert validate_policy_pack(data) == []
