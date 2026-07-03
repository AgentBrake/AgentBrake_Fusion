from agentbrake.policy_engine.compiler import PolicyRuleCompiler
from agentbrake.policy_engine.evaluator import RuleEvaluator
from agentbrake.policy_engine.fact_normalizer import FactNormalizer, IndexKey
from agentbrake.policy_engine.facts import PolicyFact, PolicyFactSet
from agentbrake.policy_engine.rule_index import RuleIndex


def test_fact_normalizer_emits_stable_index_keys():
    facts = PolicyFactSet(
        [
            PolicyFact.of("source", "has_untrusted", True),
            PolicyFact.of("asset", "touched_type", ["secret_file", "ci_workflow"]),
            PolicyFact.of("action", "parser_confidence", 0.42),
        ]
    )

    keys = FactNormalizer().keys_for_fact_set(facts)

    assert IndexKey("source.has_untrusted", "true", "exact") in keys
    assert IndexKey("asset.touched_type", "secret_file", "list_each") in keys
    assert IndexKey("asset.touched_type", "ci_workflow", "list_each") in keys
    assert IndexKey("action.parser_confidence", "lt_0_5", "range") in keys


def test_rule_index_v2_retrieval_trace_explains_postings_and_composites():
    rules = PolicyRuleCompiler().compile(
        [
            {
                "rule_id": "R-COMPOSITE",
                "category": "supply_chain",
                "decision": "block",
                "predicates": [
                    {"path": "package.source", "operator": "eq", "expected": "git_url"},
                    {"path": "source.has_untrusted", "operator": "eq", "expected": True},
                ],
            },
            {"rule_id": "R-ACTION", "match": {"action.semantic_action": "install_git_dependency"}, "decision": "block"},
        ]
    )
    facts = PolicyFactSet(
        [
            PolicyFact.of("package", "source", "git_url"),
            PolicyFact.of("source", "has_untrusted", True),
            PolicyFact.of("action", "semantic_action", "install_git_dependency"),
        ]
    )

    candidates, stats = RuleIndex(rules).candidates(facts)
    trace = stats["retrieval_trace"]

    assert {rule.rule_id for rule in candidates} == {"R-COMPOSITE", "R-ACTION"}
    assert trace["postings"]
    assert trace["composite_hits"]
    assert trace["candidate_reduction_ratio"] == 1.0


def test_indexed_candidates_cover_full_scan_hits_with_residual_rules():
    rules = PolicyRuleCompiler().compile(
        [
            {"rule_id": "R-SECRET", "match": {"asset.touched_type": "secret_file"}, "decision": "block"},
            {"rule_id": "R-SOURCE", "match": {"source.has_untrusted": True}, "decision": "block"},
            {
                "rule_id": "R-REGEX-RESIDUAL",
                "decision": "block",
                "predicates": [{"path": "asset.touched_path", "operator": "regex", "expected": r"^\.github/workflows/"}],
            },
            {
                "rule_id": "R-UNLESS-RESIDUAL",
                "match": {"action.semantic_action": "send_network_request"},
                "unless": {"contract.match": ["match"]},
                "decision": "block",
            },
        ]
    )
    facts = PolicyFactSet(
        [
            PolicyFact.of("asset", "touched_type", "secret_file"),
            PolicyFact.of("source", "has_untrusted", True),
            PolicyFact.of("asset", "touched_path", ".github/workflows/release.yml"),
            PolicyFact.of("action", "semantic_action", "send_network_request"),
            PolicyFact.of("contract", "match", "violation"),
        ]
    )

    candidates, stats = RuleIndex(rules).candidates(facts)
    indexed_hits = RuleEvaluator().evaluate(candidates, facts)
    full_hits = RuleEvaluator().evaluate(rules, facts)

    assert {hit.rule_id for hit in full_hits} <= {rule.rule_id for rule in candidates}
    assert {hit.rule_id for hit in indexed_hits} == {hit.rule_id for hit in full_hits}
    assert stats["retrieval_trace"]["residual_rules"] == 2


def test_safe_prune_uses_single_valued_impossibility_proof():
    rules = PolicyRuleCompiler().compile(
        [
            {
                "rule_id": "R-PRUNE",
                "decision": "block",
                "predicates": [
                    {"path": "action.semantic_action", "operator": "eq", "expected": "delete_repo"},
                    {"path": "source.has_untrusted", "operator": "eq", "expected": True},
                ],
            },
            {
                "rule_id": "R-KEEP",
                "decision": "block",
                "predicates": [
                    {"path": "action.semantic_action", "operator": "eq", "expected": "run_tests"},
                    {"path": "source.has_untrusted", "operator": "eq", "expected": True},
                ],
            },
        ]
    )
    facts = PolicyFactSet(
        [
            PolicyFact.of("action", "semantic_action", "run_tests"),
            PolicyFact.of("source", "has_untrusted", True),
        ]
    )

    candidates, stats = RuleIndex(rules, enable_safe_prune=True).candidates(facts)
    trace = stats["retrieval_trace"]

    assert {rule.rule_id for rule in candidates} == {"R-KEEP"}
    assert trace["safe_prune_enabled"] is True
    assert trace["pruned_rules"] == 1
    assert trace["pruned"][0]["rule_id"] == "R-PRUNE"
    assert trace["pruned"][0]["path"] == "action.semantic_action"
