from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SCRIPT = Path("experiments/agentdojo/scripts/35_check_actiongraph_ablation_acceptance.py")


def load_module():
    spec = importlib.util.spec_from_file_location("check_actiongraph", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_actiongraph_acceptance_detects_legacy_variant_in_main_table(tmp_path) -> None:
    module = load_module()
    root = tmp_path / "reports"
    source = tmp_path / "source"
    root.mkdir()
    source.mkdir()
    case = {
        "phase2_case_id": "actiongraph_banking_u1_i1",
        "case_id": "actiongraph_banking_u1_i1",
        "suite": "banking",
        "user_task_id": "u1",
        "injection_task_id": "i1",
    }
    source_case = {**case, "phase2_case_id": "ablation_banking_u1_i1", "case_id": "ablation_banking_u1_i1"}
    (source / "ablation_diagnostic_case_plan.json").write_text(json.dumps({"case_count": 1, "cases": [source_case]}), encoding="utf-8")
    plan = {"case_count": 1, "cases": [case], "variants": list(module.ACTIONGRAPH_VARIANTS)}
    (root / "actiongraph_ablation_case_plan.json").write_text(json.dumps(plan, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    (root / "actiongraph_ablation_case_plan.sha256").write_text(module.hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(), encoding="utf-8")
    for name in module.REQUIRED_FILES:
        path = root / name
        if path.exists():
            continue
        if path.suffix == ".jsonl":
            path.write_text("", encoding="utf-8")
            continue
        if path.suffix == ".json":
            path.write_text("{}", encoding="utf-8")
        else:
            path.write_text("legacy_no_context_graph\n" if name == "actiongraph_diagnostic_main_table.csv" else "ok\n", encoding="utf-8")
    result = module.check(root, source)
    assert not result["checks"]["legacy_no_context_graph_not_in_main_table"]
    assert result["structural_acceptance"] == "FAIL"
