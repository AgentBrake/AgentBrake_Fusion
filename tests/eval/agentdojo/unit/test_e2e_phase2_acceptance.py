import importlib.util
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "23_check_e2e_phase2_acceptance.py"
FIXTURE = ROOT / "tests" / "eval" / "agentdojo" / "fixtures" / "e2e_phase2_minimal"

spec = importlib.util.spec_from_file_location("check_e2e_phase2_acceptance", SCRIPT)
assert spec and spec.loader
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


def test_phase2_acceptance_passes_fixture_with_summary_only_warning(tmp_path):
    reports = tmp_path / "reports"
    shutil.copytree(FIXTURE, reports)
    report = acceptance.build_report(reports, ROOT / "experiments" / "agentdojo" / "reports" / "deepseekv4_flash")
    assert not report["failures"]
    assert any(row["name"] == "summary_only_artifact_mode" for row in report["warnings"])


def test_phase2_acceptance_fails_case_count_mismatch(tmp_path):
    reports = tmp_path / "reports"
    shutil.copytree(FIXTURE, reports)
    summary_path = reports / "e2e_summary.json"
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    data["methods"]["agentbrake_strict"]["case_count"] = 99
    summary_path.write_text(json.dumps(data), encoding="utf-8")
    report = acceptance.build_report(reports, ROOT / "experiments" / "agentdojo" / "reports" / "deepseekv4_flash")
    assert any(row["name"] == "method_case_counts_consistent" for row in report["failures"])


def test_phase2_acceptance_fails_when_agentbrake_asr_not_lower(tmp_path):
    reports = tmp_path / "reports"
    shutil.copytree(FIXTURE, reports)
    summary_path = reports / "e2e_summary.json"
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    data["methods"]["agentbrake_strict"]["targeted_asr"] = 0.75
    summary_path.write_text(json.dumps(data), encoding="utf-8")
    report = acceptance.build_report(reports, ROOT / "experiments" / "agentdojo" / "reports" / "deepseekv4_flash")
    assert any(row["name"] == "agentbrake_asr_below_no_defense" for row in report["failures"])
