import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
ITERATOR_PATH = ROOT / "experiments" / "agentdojo" / "scripts" / "08_iterate_firewall.py"


def load_iterator():
    spec = importlib.util.spec_from_file_location("iterate_firewall_08", ITERATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_iterator_default_mode_is_fair():
    module = load_iterator()
    args = module.parse_args([])
    assert args.mode == "fair"


def test_candidate_rule_requires_multiple_evidence_dimensions():
    module = load_iterator()
    sample = module.SampleRecord(
        suite="banking",
        phase="train",
        user_task_id="u",
        injection_task_id="i",
        utility=True,
        security=False,
        log_path="sample.json",
        tool_calls=[module.ToolCallSummary(name="send_money", group="financial_commit", side_effect=True)],
    )
    patches = [patch for patch in module.generate_candidate_patches([sample], mode="fair") if patch.patch_type == "rule"]
    assert patches
    assert all(len(patch.evidence_requirements) >= 3 for patch in patches)


def test_iterator_does_not_modify_fusion_py(tmp_path):
    module = load_iterator()
    sample = module.SampleRecord(
        suite="workspace",
        phase="train",
        user_task_id="u",
        injection_task_id="i",
        utility=True,
        security=False,
        log_path="sample.json",
        tool_calls=[module.ToolCallSummary(name="send_email", group="external_send", side_effect=True)],
    )
    summary = module.SafeRuleIteration(mode="fair", out_dir=tmp_path).run([sample])
    assert summary["candidate_patch_count"] >= 1
    assert (tmp_path / "candidate_rules.yaml").exists()
    assert not (tmp_path / "fusion.py").exists()


