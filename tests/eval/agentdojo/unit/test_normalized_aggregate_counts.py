import csv
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "14_generate_normalized_reports.py"
spec = importlib.util.spec_from_file_location("generate_normalized_reports_counts", SCRIPT)
assert spec and spec.loader
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


def test_aggregate_prefers_run_level_audit_counts(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    summary = {
        "run_name": "banking_agentbrake_tool_firewall",
        "suite": "banking",
        "defense": "agentdojo_firewall",
        "normalized_cases": [
            {
                "suite": "banking",
                "method": "agentdojo_firewall",
                "run_id": "banking_agentbrake_tool_firewall",
                "user_task_id": f"user_task_{idx}",
                "injection_task_id": "injection_task_0",
                "raw_agentdojo_user_task_success": True,
                "raw_agentdojo_injection_task_success": False,
                "repeated_block_count": 0,
            }
            for idx in range(16)
        ],
        "agentdojo_firewall_audit_summary": {
            "total_tool_calls_gated": 72,
            "blocked_tool_calls": 4,
            "repeated_block_count": 1,
        },
    }
    (reports / "summary.json").write_text(json.dumps(summary), encoding="utf-8")

    cases, run_aggregates = generator.collect_report_data(reports)
    rows = [case.as_normalized_dict() for case in cases]
    aggregate = generator.aggregate_rows(rows, run_aggregates)

    assert aggregate[0]["tool_call_count"] == 72
    assert aggregate[0]["blocked_tool_call_count"] == 4
    assert aggregate[0]["repeated_block_count"] == 1


def test_aggregate_csv_matches_paired_summary_counts(tmp_path):
    reports = tmp_path / "reports"
    out_dir = tmp_path / "normalized"
    reports.mkdir()
    summary = {
        "run_name": "travel_agentbrake_tool_firewall",
        "suite": "travel",
        "defense": "agentdojo_firewall",
        "normalized_cases": [
            {
                "suite": "travel",
                "method": "agentdojo_firewall",
                "run_id": "travel_agentbrake_tool_firewall",
                "user_task_id": f"user_task_{idx}",
                "injection_task_id": "injection_task_0",
                "raw_agentdojo_user_task_success": bool(idx % 2),
                "raw_agentdojo_injection_task_success": False,
            }
            for idx in range(16)
        ],
        "agentdojo_firewall_audit_summary": {
            "total_tool_calls_gated": 110,
            "blocked_tool_calls": 8,
            "repeated_block_count": 5,
        },
    }
    (reports / "summary.json").write_text(json.dumps(summary), encoding="utf-8")

    cases, run_aggregates = generator.collect_report_data(reports)
    rows = [case.as_normalized_dict() for case in cases]
    generator.write_csv(out_dir / "aggregate.csv", generator.aggregate_rows(rows, run_aggregates))

    with (out_dir / "aggregate.csv").open(newline="", encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    assert row["tool_call_count"] == "110"
    assert row["blocked_tool_call_count"] == "8"
    assert row["repeated_block_count"] == "5"


def test_main_aggregate_excludes_confirmation_modes_subtree(tmp_path):
    reports = tmp_path / "deepseekv4_flash"
    reports.mkdir()
    base = {
        "run_name": "banking_main",
        "suite": "banking",
        "defense": "agentdojo_firewall",
        "normalized_cases": [
            {
                "suite": "banking",
                "method": "agentdojo_firewall",
                "user_task_id": "user_task_0",
                "injection_task_id": "injection_task_0",
                "raw_agentdojo_user_task_success": True,
                "raw_agentdojo_injection_task_success": False,
            }
        ],
        "agentdojo_firewall_audit_summary": {"total_tool_calls_gated": 70, "blocked_tool_calls": 4, "repeated_block_count": 1},
    }
    (reports / "main.json").write_text(json.dumps(base), encoding="utf-8")
    nested = reports / "confirmation_modes"
    nested.mkdir()
    confirmation = {**base, "run_name": "banking_confirmation", "agentdojo_firewall_audit_summary": {"total_tool_calls_gated": 51, "blocked_tool_calls": 6, "repeated_block_count": 2}}
    (nested / "confirmation.json").write_text(json.dumps(confirmation), encoding="utf-8")

    cases, run_aggregates = generator.collect_report_data(reports)
    rows = [case.as_normalized_dict() for case in cases]
    aggregate = generator.aggregate_rows(rows, run_aggregates)

    assert aggregate[0]["tool_call_count"] == 70
    assert aggregate[0]["blocked_tool_call_count"] == 4
