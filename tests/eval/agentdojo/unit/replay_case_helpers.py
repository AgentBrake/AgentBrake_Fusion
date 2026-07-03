import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
REPLAY_RUNNER = ROOT / "experiments" / "agentdojo" / "scripts" / "11_run_replay_benchmark.py"
DERIVED_CASES = ROOT / "experiments" / "agentdojo" / "replay_cases" / "agentdojo_derived"

spec = importlib.util.spec_from_file_location("agentdojo_replay_runner", REPLAY_RUNNER)
assert spec and spec.loader
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def run_replay_case(case_id: str) -> dict:
    path = next(DERIVED_CASES.rglob(f"{case_id}.json"))
    case = json.loads(path.read_text(encoding="utf-8"))
    return runner.run_case(case)
