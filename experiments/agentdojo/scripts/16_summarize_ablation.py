from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REPORTS = ROOT / "experiments" / "agentdojo" / "reports"


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize AgentDojo firewall ablation execution evidence")
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS)
    parser.add_argument("--out", type=Path, default=DEFAULT_REPORTS / "ablation_summary.json")
    args = parser.parse_args()
    summary = summarize_ablation(args.reports_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(args.out)
    return 0


def summarize_ablation(reports_dir: Path) -> dict[str, Any]:
    executed: Counter[str] = Counter()
    skipped: Counter[str] = Counter()
    matched_rules: Counter[str] = Counter()
    configs: Counter[str] = Counter()
    event_count = 0
    for event in iter_decision_events(reports_dir):
        event_count += 1
        executed.update(event.get("modules_executed") or [])
        skipped.update(event.get("modules_skipped") or [])
        matched_rules.update(event.get("matched_rules") or event.get("reason_codes") or [])
        configs.update([json.dumps(event.get("ablation_config") or {}, sort_keys=True)])
    return {
        "event_count": event_count,
        "modules_executed": dict(sorted(executed.items())),
        "modules_skipped": dict(sorted(skipped.items())),
        "matched_rules": dict(sorted(matched_rules.items())),
        "ablation_configs_seen": dict(sorted(configs.items())),
    }


def iter_decision_events(reports_dir: Path):
    for path in sorted(reports_dir.rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        yield from events_from_json(data)


def events_from_json(data: Any):
    if isinstance(data, dict):
        if data.get("event_type") == "agentdojo_tool_gate_decision":
            yield data
        for key in ("audit", "events", "audit_events"):
            value = data.get(key)
            if isinstance(value, list):
                for item in value:
                    yield from events_from_json(item)
        for row in data.get("results", []) if isinstance(data.get("results"), list) else []:
            yield from events_from_json(row)
    elif isinstance(data, list):
        for item in data:
            yield from events_from_json(item)


if __name__ == "__main__":
    raise SystemExit(main())
