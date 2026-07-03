from agentbrake.policy_engine.compiler import PolicyRuleCompiler
from agentbrake.policy_engine.facts import PolicyFact, PolicyFactSet
from agentbrake.policy_engine.rule_index import RuleIndex


def test_rule_index_uses_multiple_fact_dimensions():
    rules = PolicyRuleCompiler().compile(
        [
            {
                "rule_id": "R-ACTION",
                "name": "a",
                "category": "x",
                "match": {"action.semantic_action": "send_network_request"},
                "decision": "block",
            },
            {"rule_id": "R-SOURCE", "name": "s", "category": "x", "match": {"source.trust_floor": "untrusted"}, "decision": "block"},
            {"rule_id": "R-ASSET", "name": "asset", "category": "x", "match": {"asset.touched_type": "secret_file"}, "decision": "block"},
            {"rule_id": "R-PKG", "name": "pkg", "category": "x", "match": {"package.source": "git_url"}, "decision": "block"},
            {"rule_id": "R-SECRET", "name": "sec", "category": "x", "match": {"secret.event": "egress_after_secret"}, "decision": "block"},
            {"rule_id": "R-CONTRACT", "name": "c", "category": "x", "match": {"contract.match": "violation"}, "decision": "block"},
            {"rule_id": "R-MCP", "name": "m", "category": "x", "match": {"mcp.capability": "deploy"}, "decision": "block"},
        ]
    )
    facts = PolicyFactSet(
        [
            PolicyFact.of("action", "semantic_action", "send_network_request"),
            PolicyFact.of("source", "trust_floor", "untrusted"),
            PolicyFact.of("asset", "touched_type", "secret_file"),
            PolicyFact.of("package", "source", "git_url"),
            PolicyFact.of("secret", "event", "egress_after_secret"),
            PolicyFact.of("contract", "match", "violation"),
            PolicyFact.of("mcp", "capability", "deploy"),
        ]
    )

    candidates, stats = RuleIndex(rules).candidates(facts)

    assert {rule.rule_id for rule in candidates} == {"R-ACTION", "R-SOURCE", "R-ASSET", "R-PKG", "R-SECRET", "R-CONTRACT", "R-MCP"}
    assert stats["candidate_rules"] == 7
    assert stats["by_asset_type"] >= 1
