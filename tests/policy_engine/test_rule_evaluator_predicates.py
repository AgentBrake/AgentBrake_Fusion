from agentbrake.policy_engine.compiler import PolicyRuleCompiler
from agentbrake.policy_engine.evaluator import RuleEvaluator
from agentbrake.policy_engine.facts import PolicyFact, PolicyFactSet


def test_rule_evaluator_supports_predicates_and_evidence_refs():
    rules = PolicyRuleCompiler().compile(
        [
            {
                "rule_id": "R-PRED",
                "name": "predicate_rule",
                "category": "test",
                "decision": "block",
                "predicates": [
                    {"path": "source.trust_floor", "operator": "in", "expected": ["untrusted", "tainted"]},
                    {"path": "asset.touched_path", "operator": "regex", "expected": r"^\.github/workflows/"},
                    {"path": "action.parser_confidence", "operator": "lte", "expected": 0.5},
                ],
                "unless": {"contract.match": ["match"]},
            }
        ]
    )
    facts = PolicyFactSet(
        [
            PolicyFact.of("source", "trust_floor", "untrusted", evidence_refs=["src_1"]),
            PolicyFact.of("asset", "touched_path", ".github/workflows/deploy.yml", evidence_refs=["asset_1"]),
            PolicyFact.of("action", "parser_confidence", 0.4, evidence_refs=["act_1"]),
            PolicyFact.of("contract", "match", "violation", evidence_refs=["task_1"]),
        ]
    )

    hits = RuleEvaluator().evaluate(rules, facts)

    assert len(hits) == 1
    assert {"src_1", "asset_1", "act_1"} <= set(hits[0].evidence_refs)
    assert all(pred["matched"] for pred in hits[0].predicates[:3])


def test_rule_evaluator_supports_unless():
    rules = PolicyRuleCompiler().compile(
        [
            {
                "rule_id": "R-UNLESS",
                "name": "unless_rule",
                "category": "test",
                "decision": "block",
                "match": {"action.semantic_action": "send_network_request"},
                "unless": {"contract.match_any": ["match"]},
            }
        ]
    )
    facts = PolicyFactSet(
        [
            PolicyFact.of("action", "semantic_action", "send_network_request"),
            PolicyFact.of("contract", "match", "match"),
        ]
    )

    assert RuleEvaluator().evaluate(rules, facts) == []
