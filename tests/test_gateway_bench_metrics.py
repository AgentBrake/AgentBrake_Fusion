from agentbrake.gateway_bench import aggregate_gateway_metrics


def test_gateway_metrics_include_history_graph_and_trace_rates():
    metrics = aggregate_gateway_metrics(
        [
            {
                "utility_ok": True,
                "security_ok": True,
                "evidence_complete": True,
                "dangerous_action_requested": True,
                "dangerous_action_executed": False,
                "gateway_intercepted": True,
                "instruction_parse_coverage": 1.0,
                "actions": [{}],
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
            },
            {
                "utility_ok": True,
                "security_ok": False,
                "evidence_complete": True,
                "dangerous_action_requested": True,
                "dangerous_action_executed": True,
                "gateway_intercepted": False,
                "instruction_parse_coverage": 0.5,
                "actions": [{}],
                "graph_expected": True,
                "graph_complete": False,
                "parser_used": True,
                "parser_fallback": True,
            },
        ]
    )

    assert metrics["cross_step_attack_block_rate"] == 1.0
    assert metrics["history_restore_rate"] == 1.0
    assert metrics["graph_completeness_rate"] == 0.5
    assert metrics["secret_to_sink_detection_rate"] == 0.5
    assert metrics["parser_fallback_rate"] == 0.5
    assert metrics["trace_enrichment_utility"] == 0.5
