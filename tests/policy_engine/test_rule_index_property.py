import random

from agentbrake.policy_engine.compiler import PolicyRuleCompiler
from agentbrake.policy_engine.evaluator import RuleEvaluator
from agentbrake.policy_engine.facts import PolicyFact, PolicyFactSet
from agentbrake.policy_engine.rule_index import RuleIndex

FACT_DOMAINS = {
    "action.semantic_action": ["run_tests", "send_network_request", "edit_source_file", "install_git_dependency"],
    "action.network_capability": [True, False],
    "source.has_untrusted": [True, False],
    "contract.match": ["match", "partial_match", "violation", "unknown"],
    "package.source": ["registry", "git_url", "tarball_url"],
    "asset.touched_type": ["source_file", "secret_file", "ci_workflow"],
    "graph.has_dataflow_edge": [True, False],
    "flow.secret_to_external": [True, False],
    "history.secret_taint": [True, False],
}


def test_indexed_retrieval_matches_full_scan_for_random_policy_sets():
    rng = random.Random(1337)
    compiler = PolicyRuleCompiler()
    evaluator = RuleEvaluator()

    for case in range(40):
        raw_rules = [_random_rule(rng, case, idx) for idx in range(36)]
        rules = compiler.compile(raw_rules)
        facts = _random_facts(rng)

        candidates, _stats = RuleIndex(rules).candidates(facts)
        full_hits = evaluator.evaluate(rules, facts)
        indexed_hits = evaluator.evaluate(candidates, facts)

        assert {hit.rule_id for hit in indexed_hits} == {hit.rule_id for hit in full_hits}
        assert {hit.rule_id for hit in full_hits} <= {rule.rule_id for rule in candidates}


def _random_rule(rng: random.Random, case: int, idx: int) -> dict[str, object]:
    path = rng.choice(list(FACT_DOMAINS))
    values = FACT_DOMAINS[path]
    op = rng.choice(["eq", "in", "eq", "eq"])
    expected = rng.choice(values)
    predicate: dict[str, object] = {"path": path, "operator": op, "expected": expected}
    if op == "in":
        predicate["expected"] = rng.sample(values, k=min(len(values), rng.randint(1, 2)))

    predicates = [predicate]
    if idx % 9 == 0:
        predicates.append({"path": "asset.touched_path", "operator": "regex", "expected": r"^\.github/workflows/"})
    elif idx % 7 == 0:
        other_path = rng.choice(list(FACT_DOMAINS))
        predicates.append({"path": other_path, "operator": "exists", "expected": None})

    return {
        "rule_id": f"R-{case}-{idx}",
        "category": "property",
        "decision": rng.choice(["allow", "allow_in_sandbox", "sandbox_then_approval", "block"]),
        "predicates": predicates,
    }


def _random_facts(rng: random.Random) -> PolicyFactSet:
    facts = [
        PolicyFact.of("action", "semantic_action", rng.choice(FACT_DOMAINS["action.semantic_action"])),
        PolicyFact.of("action", "network_capability", rng.choice(FACT_DOMAINS["action.network_capability"])),
        PolicyFact.of("source", "has_untrusted", rng.choice(FACT_DOMAINS["source.has_untrusted"])),
        PolicyFact.of("contract", "match", rng.choice(FACT_DOMAINS["contract.match"])),
        PolicyFact.of("package", "source", rng.choice(FACT_DOMAINS["package.source"])),
        PolicyFact.of("graph", "has_dataflow_edge", rng.choice(FACT_DOMAINS["graph.has_dataflow_edge"])),
        PolicyFact.of("flow", "secret_to_external", rng.choice(FACT_DOMAINS["flow.secret_to_external"])),
        PolicyFact.of("history", "secret_taint", rng.choice(FACT_DOMAINS["history.secret_taint"])),
    ]
    touched = rng.sample(FACT_DOMAINS["asset.touched_type"], k=rng.randint(1, 2))
    facts.append(PolicyFact.of("asset", "touched_type", touched))
    if "ci_workflow" in touched:
        facts.append(PolicyFact.of("asset", "touched_path", ".github/workflows/ci.yml"))
    return PolicyFactSet(facts)
