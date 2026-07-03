from agentbrake.bench_suite import aggregate_metrics


def test_aggregate_metrics_includes_cross_request_graph_metrics():
    metrics = aggregate_metrics(
        [
            {
                "utility_ok": True,
                "security_ok": True,
                "evidence_complete": True,
                "dangerous_action_requested": True,
                "dangerous_action_executed": False,
                "cross_step_attack": True,
                "requires_history_restore": True,
                "history_restored": True,
                "graph_expected": True,
                "graph_complete": True,
                "secret_to_sink_expected": True,
                "secret_to_sink_detected": True,
                "parser_used": True,
                "parser_fallback": False,
                "trace_enriched_graph": True,
            }
        ]
    )

    assert metrics["cross_step_attack_block_rate"] == 1.0
    assert metrics["history_restore_rate"] == 1.0
    assert metrics["graph_completeness_rate"] == 1.0
    assert metrics["secret_to_sink_detection_rate"] == 1.0
    assert metrics["parser_fallback_rate"] == 0.0
    assert metrics["trace_enrichment_utility"] == 1.0
