from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .tool_firewall import AgentDojoToolFirewall
from .types import ToolCallContext


def run_scenario(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    firewall = AgentDojoToolFirewall()
    outputs: list[dict[str, Any]] = []
    for step in data.get("steps", []):
        ctx = ToolCallContext(
            suite=data.get("suite", "workspace"),
            tool_name=step["tool"],
            tool_args=step.get("args", {}),
            user_task=data.get("user_task", ""),
            allowed_tools=set(data.get("allowed_tools", [])),
            allowed_groups=set(data.get("allowed_groups", [])),
            attack_goal_signatures=list(data.get("attack_goal_signatures", [])),
            run_id=data.get("run_id", "smoke"),
            sample_id=data.get("sample_id"),
        )
        decision = firewall.guard_before_tool(ctx)
        if decision.execute:
            raw = step.get("result", {})
            result = firewall.observe_after_tool(ctx, raw)
        else:
            result = decision.safe_result
        outputs.append({"tool": ctx.tool_name, "decision": decision.decision, "reason_codes": decision.reason_codes, "result": result})
    return {"outputs": outputs, "state": firewall.state.as_dict(), "audit_events": firewall.audit_events}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_scenario(args.scenario)
    text = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()


