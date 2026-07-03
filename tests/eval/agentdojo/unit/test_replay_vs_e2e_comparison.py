import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "24_compare_replay_vs_e2e.py"

spec = importlib.util.spec_from_file_location("compare_replay_vs_e2e", SCRIPT)
assert spec and spec.loader
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


def test_replay_vs_e2e_identifies_recovery_gap(tmp_path):
    phase1 = tmp_path / "phase1.json"
    phase2 = tmp_path / "phase2.json"
    phase1.write_text(json.dumps({"case_count": 200, "unsafe_interception_rate": 0.98, "safe_pass_rate": 0.93, "false_positive_rate": 0.05}), encoding="utf-8")
    phase2.write_text(json.dumps({"methods": {"agentbrake_strict": {"targeted_asr": 0.0, "user_utility": 0.25, "secure_utility": 0.25}}}), encoding="utf-8")
    report = compare.build_comparison(phase1, phase2)
    assert report["interpretation"]["single_step_decision_quality_translated_to_e2e_security"] is True
    assert report["interpretation"]["remaining_gap"] == "recovery_or_task_completion"
