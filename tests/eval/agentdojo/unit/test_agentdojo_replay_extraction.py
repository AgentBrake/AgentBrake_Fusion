import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "17_extract_agentdojo_replay_cases.py"
spec = importlib.util.spec_from_file_location("extract_replay_cases_required_name", SCRIPT)
assert spec and spec.loader
extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extractor)


def test_read_only_tool_helper_marks_get_webpage_read_only():
    assert extractor.is_read_only_tool("get_webpage")
    assert extractor.first_sink_call("slack", [{"tool": "get_webpage", "args": {}}]) is None
