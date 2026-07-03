from agentbrake.policy_engine.evidence_graph import PolicyEvaluationTrace
from agentbrake.policy_engine.facts import PolicyFact, PolicyFactSet
from agentbrake.policy_engine.rule_schema import RuleHit


def test_policy_eval_trace_contains_causal_graph_edges():
    fact = PolicyFact.of("asset", "touched_type", "secret_file", evidence_refs=["asset_1"])
    hit = RuleHit(
        "INV-SECRET-001",
        "secret",
        "secret",
        "block",
        100,
        ["secret_asset_touched"],
        ["block"],
        ["asset_1"],
        True,
        [
            {
                "predicate_id": "pred_1",
                "path": "asset.touched_type",
                "operator": "in",
                "expected": ["secret_file"],
                "actual": ["secret_file"],
                "matched": True,
                "matched_fact_ids": [fact.fact_id],
                "evidence_refs": ["asset_1"],
            }
        ],
    )

    trace = PolicyEvaluationTrace.build(
        action_id="act_1",
        engine_mode="msj-enforce",
        policy_version="agentbrake-fusion-msj-v0.4",
        fact_set=PolicyFactSet([fact]),
        final_decision="block",
        hits=[hit],
        lattice_path=[{"from": "allow", "to": "block", "via": "INV-SECRET-001"}],
    )

    assert trace.fact_nodes
    assert trace.trace_type == "BrakeTrace"
    assert trace.decision_model == "AgentBrake-Fusion/MSJ Engine"
    assert trace.constraint_product_lattice_path == trace.decision_lattice_path
    assert trace.predicate_nodes
    assert trace.rule_nodes
    assert {"from": fact.fact_id, "to": "pred_1", "relation": "matched"} in trace.edges


def test_policy_eval_trace_preserves_graph_history_and_trace_metadata():
    graph_fact = PolicyFact.of(
        "graph",
        "confidence_min",
        0.72,
        confidence=0.72,
        metadata={"parser": "powershell", "observed": True, "warnings": ["partial_parse"]},
    )
    history_fact = PolicyFact.of(
        "history",
        "state_hash",
        "sha256:abc",
        metadata={"state_hash": "sha256:abc", "restore_source": "file"},
    )
    trace_fact = PolicyFact.of("trace", "enriched_graph", True, metadata={"trace_id": "trace_1"})

    trace = PolicyEvaluationTrace.build(
        action_id="act_2",
        engine_mode="msj-enforce",
        policy_version="agentbrake-fusion-msj-v0.4",
        fact_set=PolicyFactSet([graph_fact, history_fact, trace_fact]),
        final_decision="block",
        hits=[],
        lattice_path=[],
    )

    graph_node = next(node for node in trace.action_graph_nodes if node["kind"] == "action_graph_node")
    history_node = trace.history_nodes[0]

    assert graph_node["parser"] == "powershell"
    assert graph_node["confidence"] == 0.72
    assert graph_node["observed"] is True
    assert history_node["state_hash"] == "sha256:abc"
    assert history_node["restore_source"] == "file"
    assert any(node["kind"] == "trace_enrichment_node" for node in trace.action_graph_nodes)
