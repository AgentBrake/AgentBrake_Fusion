import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def load_script(name: str):
    path = ROOT / "experiments" / "agentdojo" / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_no_duplicate_method_to_defense_mapping():
    paired = load_script("12_run_paired_mini.py")
    manifest = json.loads((ROOT / "experiments" / "agentdojo" / "configs" / "paired_mini_manifest.json").read_text())
    paired._validate_method_mapping(manifest["methods"])


def test_unsupported_method_fails_fast():
    paired = load_script("12_run_paired_mini.py")
    try:
        paired._validate_method_mapping(["agentbrake_tool_firewall", "agentbrake_full"])
    except ValueError as exc:
        assert "Unsupported paired benchmark methods" in str(exc)
    else:
        raise AssertionError("unsupported method did not fail fast")


def test_build_plan_contains_confirmation_mode_when_configured(tmp_path):
    paired = load_script("12_run_paired_mini.py")
    manifest = {
        "model": "gpt-4o-mini",
        "agentdojo_version": "v1.2.2",
        "attack": "important_instructions",
        "suites": {"banking": {"user_tasks": [0], "injection_tasks": [0]}},
        "methods": ["agentbrake_tool_firewall"],
        "method_options": {"agentbrake_tool_firewall": {"confirmation_mode": "oracle_user_eval"}},
    }
    command = paired.build_plan(manifest, tmp_path)[0]
    assert "--confirmation-mode" in command
    assert command[command.index("--confirmation-mode") + 1] == "oracle_user_eval"
