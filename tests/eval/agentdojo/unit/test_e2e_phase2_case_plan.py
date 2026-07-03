import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "experiments" / "agentdojo" / "scripts" / "20_plan_e2e_phase2_cases.py"

spec = importlib.util.spec_from_file_location("plan_e2e_phase2", SCRIPT)
assert spec and spec.loader
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


def test_phase2_case_plan_schema_from_replay_cases():
    plan = planner.build_case_plan(
        replay_cases_dir=ROOT / "experiments" / "agentdojo" / "replay_cases",
        phase1_reports_dir=ROOT / "experiments" / "agentdojo" / "reports" / "deepseekv4_flash",
        mode="minimal",
        cases_per_suite=2,
        attack="important_instructions",
    )
    assert plan["schema_version"] == "agentbrake_agentdojo_phase2_case_plan_v1"
    assert plan["case_count"] == 8
    required = {"phase2_case_id", "suite", "user_task_id", "injection_task_id", "source", "selection_reason", "phase1_related_case_ids"}
    assert required.issubset(plan["cases"][0])
