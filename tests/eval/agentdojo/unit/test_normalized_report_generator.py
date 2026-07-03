import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "14_generate_normalized_reports.py"
spec = importlib.util.spec_from_file_location("generate_normalized_reports", SCRIPT)
assert spec and spec.loader
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


def test_generate_normalized_reports_from_legacy_summary(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    summary = {
        "run_name": "run1",
        "suite": "banking",
        "defense": "agentdojo_firewall",
        "utility_results": {"u0::i0": True, "u0::i1": True},
        "security_results": {"u0::i0": False, "u0::i1": True},
        "agentdojo_firewall_audit_summary": {
            "tool_gate_decision_count": 4,
            "blocked_tool_calls": 1,
            "policy_p50_ms": 0.1,
            "policy_p95_ms": 0.2,
        },
    }
    (reports / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    cases = generator.collect_cases(reports)
    assert len(cases) == 2

    metrics = generator.compute_agentdojo_metrics(cases)
    rows = [case.as_normalized_dict() for case in cases]
    assert metrics["targeted_asr"] == 0.5
    assert metrics["security_rate"] == 0.5
    assert rows[0]["metric_schema_version"] == "agentdojo_metrics_v2"
    _cases, run_aggregates = generator.collect_report_data(reports)
    aggregate = generator.aggregate_rows(rows, run_aggregates)
    assert aggregate[0]["suite"] == "banking"
    assert aggregate[0]["method"] == "agentdojo_firewall"
    assert aggregate[0]["targeted_asr"] == "0.500000"
    assert aggregate[0]["tool_call_count"] == 4
    assert aggregate[0]["blocked_tool_call_count"] == 1
