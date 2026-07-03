from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SCRIPT = Path("experiments/agentdojo/scripts/31_plan_ablation_diagnostic.py")


def load_module():
    spec = importlib.util.spec_from_file_location("plan_ablation", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_full_fixture(root: Path) -> None:
    trace_dir = root / "full_traces" / "no_defense" / "banking" / "none" / "user_task_1"
    trace_dir.mkdir(parents=True)
    (trace_dir / "injection_task_1.json").write_text(json.dumps({"tool_calls": [{"tool": "send_money"}]}), encoding="utf-8")
    strict_trace_dir = root / "full_traces" / "agentbrake_strict" / "banking" / "agentdojo_firewall" / "user_task_1"
    strict_trace_dir.mkdir(parents=True)
    (strict_trace_dir / "injection_task_1.json").write_text(json.dumps({"tool_calls": [{"tool": "send_money"}]}), encoding="utf-8")
    rows = [
        {
            "suite": "banking",
            "method": "no_defense",
            "user_task_id": "user_task_1",
            "injection_task_id": "injection_task_1",
            "raw_agentdojo_injection_task_success": True,
            "raw_agentdojo_user_task_success": False,
            "trace_file": "full_traces/no_defense/banking/none/user_task_1/injection_task_1.json",
        },
        {
            "suite": "banking",
            "method": "agentbrake_strict",
            "user_task_id": "user_task_1",
            "injection_task_id": "injection_task_1",
            "blocked_case": True,
            "raw_agentdojo_user_task_success": False,
            "trace_file": "full_traces/agentbrake_strict/banking/agentdojo_firewall/user_task_1/injection_task_1.json",
        },
    ]
    for idx in range(2, 5):
        rows.extend(
            [
                {
                    "suite": "banking",
                    "method": "no_defense",
                    "user_task_id": f"user_task_{idx}",
                    "injection_task_id": "injection_task_1",
                    "raw_agentdojo_injection_task_success": False,
                    "raw_agentdojo_user_task_success": True,
                    "trace_file": "full_traces/no_defense/banking/none/user_task_1/injection_task_1.json",
                },
                {
                    "suite": "banking",
                    "method": "agentbrake_strict",
                    "user_task_id": f"user_task_{idx}",
                    "injection_task_id": "injection_task_1",
                    "blocked_case": False,
                    "raw_agentdojo_user_task_success": True,
                    "trace_file": "full_traces/agentbrake_strict/banking/agentdojo_firewall/user_task_1/injection_task_1.json",
                },
            ]
        )
    (root / "per_case_results.jsonl").write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")


def test_planner_dedup_sort_target_and_sha(tmp_path: Path) -> None:
    module = load_module()
    full = tmp_path / "full"
    full.mkdir()
    write_full_fixture(full)
    out = tmp_path / "out"
    assert (
        module.main_from_args
        if hasattr(module, "main_from_args")
        else True
    )
    import sys

    old = sys.argv
    try:
        sys.argv = [
            "x",
            "--full-e2e-dir",
            str(full),
            "--out-dir",
            str(out),
            "--target-size",
            "3",
            "--blocked-critical-cap",
            "1",
        ]
        assert module.main() == 0
    finally:
        sys.argv = old
    plan = json.loads((out / "ablation_diagnostic_case_plan.json").read_text(encoding="utf-8"))
    assert plan["case_count"] == 3
    keys = [(c["suite"], c["user_task_id"], c["injection_task_id"]) for c in plan["cases"]]
    assert len(keys) == len(set(keys))
    assert plan["cases"][0]["selection_reason"] == "attack_active"
    first_digest = (out / "ablation_diagnostic_case_plan.sha256").read_text(encoding="utf-8")
    sys.argv = old
    try:
        sys.argv = ["x", "--full-e2e-dir", str(full), "--out-dir", str(out), "--target-size", "3", "--blocked-critical-cap", "1"]
        assert module.main() == 0
    finally:
        sys.argv = old
    assert (out / "ablation_diagnostic_case_plan.sha256").read_text(encoding="utf-8") == first_digest
