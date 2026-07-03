import runpy
from pathlib import Path

if __name__ == "__main__":
    target = Path(__file__).with_name("29_plan_qwen_replay_gap_cases.py")
    runpy.run_path(str(target), run_name="__main__")
