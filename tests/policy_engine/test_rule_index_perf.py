from time import perf_counter

from agentbrake.policy_engine.compiler import PolicyRuleCompiler
from agentbrake.policy_engine.facts import PolicyFact, PolicyFactSet
from agentbrake.policy_engine.rule_index import RuleIndex


def test_rule_index_keeps_large_policy_pack_candidate_set_small():
    rules = PolicyRuleCompiler().compile(_synthetic_policy_pack(1000))
    facts = PolicyFactSet(
        [
            PolicyFact.of("action", "semantic_action", "target_action"),
            PolicyFact.of("source", "has_untrusted", True),
            PolicyFact.of("contract", "match", "violation"),
            PolicyFact.of("package", "source", "registry"),
        ]
    )

    index = RuleIndex(rules)
    elapsed = []
    last_candidates = []
    last_stats = {}
    for _ in range(8):
        started = perf_counter()
        last_candidates, last_stats = index.candidates(facts)
        elapsed.append(perf_counter() - started)

    trace = last_stats["retrieval_trace"]
    assert len(last_candidates) < 90
    assert trace["candidate_reduction_ratio"] < 0.1
    assert max(elapsed) < 1.0


def _synthetic_policy_pack(size: int) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    for idx in range(size):
        if idx % 20 == 0:
            semantic = "target_action"
        elif idx % 3 == 0:
            semantic = f"other_action_{idx}"
        elif idx % 3 == 1:
            semantic = "install_git_dependency"
        else:
            semantic = "send_network_request"

        predicates: list[dict[str, object]] = [{"path": "action.semantic_action", "operator": "eq", "expected": semantic}]
        if idx % 5 == 0:
            predicates.append({"path": "contract.match", "operator": "eq", "expected": "match"})
        elif idx % 7 == 0:
            predicates.append({"path": "package.source", "operator": "eq", "expected": "git_url"})
        elif idx % 11 == 0:
            predicates.append({"path": "source.has_untrusted", "operator": "eq", "expected": False})

        rules.append(
            {
                "rule_id": f"PERF-{idx}",
                "category": "perf",
                "decision": "block",
                "predicates": predicates,
            }
        )
    return rules
