from __future__ import annotations

import hashlib
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


def test_actiongraph_plan_reuses_exact_source_cases(tmp_path) -> None:
    module = load_module()
    source = {
        "case_count": 2,
        "cases": [
            {
                "phase2_case_id": "ablation_banking_u1_i1",
                "case_id": "ablation_banking_u1_i1",
                "suite": "banking",
                "user_task_id": "u1",
                "injection_task_id": "i1",
                "selection_reason": "attack_active",
                "primary_side_effect_tool": "send_money",
            },
            {
                "phase2_case_id": "ablation_slack_u2_i2",
                "case_id": "ablation_slack_u2_i2",
                "suite": "slack",
                "user_task_id": "u2",
                "injection_task_id": "i2",
                "selection_reason": "safe_side_effect_control",
                "primary_side_effect_tool": "send_email",
            },
        ],
    }
    source_path = tmp_path / "ablation_diagnostic_case_plan.json"
    source_path.write_text(json.dumps(source), encoding="utf-8")
    args = type(
        "Args",
        (),
        {
            "source_case_plan": source_path,
            "out_dir": tmp_path / "out",
            "model": "qwen-plus",
            "attack": "important_instructions",
        },
    )()

    assert module.plan_actiongraph_same_cases(args) == 0
    plan = json.loads((args.out_dir / "actiongraph_ablation_case_plan.json").read_text(encoding="utf-8"))
    old_keys = {(c["suite"], c["user_task_id"], c["injection_task_id"]) for c in source["cases"]}
    new_keys = {(c["suite"], c["user_task_id"], c["injection_task_id"]) for c in plan["cases"]}
    assert old_keys == new_keys
    assert plan["case_selection_source_model"] == "deepseek-v4-flash"
    assert plan["evaluation_model"] == "qwen-plus"
    assert plan["cases"][0]["source_ablation_case_id"] == "ablation_banking_u1_i1"
    expected = hashlib.sha256(module.canonical_json(plan).encode("utf-8")).hexdigest()
    assert (args.out_dir / "actiongraph_ablation_case_plan.sha256").read_text(encoding="utf-8") == expected
