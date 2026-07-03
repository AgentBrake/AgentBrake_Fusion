import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "17_extract_agentdojo_replay_cases.py"
REPLAY = ROOT / "experiments" / "agentdojo" / "replay_cases"
DERIVED = REPLAY / "agentdojo_derived"

spec = importlib.util.spec_from_file_location("extract_agentdojo_replay_cases", SCRIPT)
assert spec and spec.loader
extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extractor)


def test_extractor_uses_suite_specific_sinks_without_first_tool_fallback():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "DANGEROUS_SINKS" in source
    assert "DANGEROUS_SINK_KEYWORDS" not in source
    assert "return normalized[0] if normalized else None" not in source
    assert "get_webpage" not in extractor.DANGEROUS_SINKS["slack"]
    assert "post_webpage" in extractor.EXTERNAL_WRITE_SINKS


def test_counted_unsafe_cases_do_not_include_get_webpage_or_read_only_tools():
    read_only_prefixes = ("get_", "read_", "search_", "list_", "lookup", "open_")
    for path in (DERIVED / "unsafe").glob("*.json"):
        case = json.loads(path.read_text(encoding="utf-8"))
        tool = (case.get("current_tool_call") or {}).get("tool", "")
        assert tool != "get_webpage"
        assert not str(tool).startswith(read_only_prefixes)


def test_safe_cases_require_user_success_and_injection_failure():
    for path in (DERIVED / "safe").glob("*.json"):
        case = json.loads(path.read_text(encoding="utf-8"))
        assert case["expected_agentdojo_user_success"] is True
        assert case["expected_agentdojo_injection_success"] is False


def test_local_allow_candidates_are_not_formal_cases():
    manifest = json.loads((REPLAY / "manifest_agentdojo_derived.json").read_text(encoding="utf-8"))
    safe_count = len(list((DERIVED / "safe").glob("*.json")))
    unsafe_count = len(list((DERIVED / "unsafe").glob("*.json")))
    local_allow_count = len(list((DERIVED / "local_allow_candidates").glob("*.json")))
    assert manifest["case_count"] == safe_count + unsafe_count
    assert manifest["local_allow_candidate_count"] == local_allow_count


def test_review_records_have_stable_case_ids():
    for line in (REPLAY / "review_queue.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        assert row.get("case_id")


def test_sample_gap_report_has_phase1_counts():
    report = (REPLAY / "sample_gap_report.md").read_text(encoding="utf-8")
    manifest = json.loads((REPLAY / "manifest_agentdojo_derived.json").read_text(encoding="utf-8"))
    assert manifest["unsafe_case_count"] >= 55
    assert manifest["safe_case_count"] >= 89
    assert "Phase 1 unsafe shortfall: 0" in report
    assert "Phase 1 safe shortfall: 0" in report
    assert "Estimated minimum additional DeepSeek calls for Phase 1: 0" in report


def test_manifest_counts_match_file_counts():
    manifest = json.loads((REPLAY / "manifest_agentdojo_derived.json").read_text(encoding="utf-8"))
    assert manifest["unsafe_case_count"] == len(list((DERIVED / "unsafe").glob("*.json")))
    assert manifest["safe_case_count"] == len(list((DERIVED / "safe").glob("*.json")))
