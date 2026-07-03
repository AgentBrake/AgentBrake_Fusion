from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Materialize an Agent-SafetyBench pilot subset from a case plan.")
    parser.add_argument("--data", default="experiments/agent_safetybench/upstream/data/released_data.json")
    parser.add_argument("--plan", default="experiments/agent_safetybench/case_plans/agentbrake_non_agentdojo_pilot_32.json")
    parser.add_argument("--out", default="experiments/agent_safetybench/case_plans/agentbrake_non_agentdojo_pilot_32_cases.json")
    args = parser.parse_args()

    data = json.loads(Path(args.data).read_text(encoding="utf-8"))
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    ids = {str(item) for item in plan["case_ids"]}
    selected = [case for case in data if str(case.get("id")) in ids]
    if len(selected) != len(ids):
        found = {str(case.get("id")) for case in selected}
        missing = sorted(ids - found, key=int)
        raise SystemExit(f"Missing case ids in source data: {missing}")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(selected, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(selected)} cases to {out}")


if __name__ == "__main__":
    main()
