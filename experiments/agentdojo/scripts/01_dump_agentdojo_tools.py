from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentbrake.eval.agentdojo.evidence.taxonomy import AgentDojoToolTaxonomy

try:
    from agentdojo.task_suite import get_suite  # type: ignore
except Exception:  # pragma: no cover
    try:
        from agentdojo.task_suite.load_suites import get_suite  # type: ignore
    except Exception as exc:  # pragma: no cover
        get_suite = None  # type: ignore[assignment]
        IMPORT_ERROR = exc
    else:
        IMPORT_ERROR = None
else:
    IMPORT_ERROR = None


ROOT = Path(__file__).resolve().parents[3]
REPORT_DIR = ROOT / "experiments" / "agentdojo" / "reports"
SUITES = ("banking", "slack", "workspace", "travel", "workspace_plus")


def suite_tool_names(suite_name: str, benchmark_version: str = "v1.2.2") -> tuple[list[str], str | None]:
    if get_suite is None:
        return [], f"AgentDojo get_suite import failed: {IMPORT_ERROR!r}"
    try:
        suite = get_suite(benchmark_version, suite_name)
    except Exception as exc:
        return [], f"could not load suite {suite_name}: {exc!r}"
    try:
        tools = getattr(suite, "tools")
        return sorted({str(getattr(tool, "name", "")) for tool in tools if getattr(tool, "name", "")}), None
    except Exception:
        pass
    try:
        runtime = suite.load_and_inject_default_environment({})
        functions = getattr(runtime, "functions", {})
        return sorted(str(name) for name in functions), None
    except Exception as exc:
        return [], f"could not extract tools from suite {suite_name}: {exc!r}"


def main() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    taxonomy = AgentDojoToolTaxonomy()
    per_suite: dict[str, dict[str, Any]] = {}
    all_tools: set[str] = set()
    errors: dict[str, str] = {}

    for suite_name in SUITES:
        names, error = suite_tool_names(suite_name)
        if error:
            errors[suite_name] = error
        all_tools.update(names)
        coverage = taxonomy.coverage(names, suite=suite_name)
        per_suite[suite_name] = {
            "official_tool_count": len(names),
            "official_tools": names,
            "registered_tools": sorted(set(names) - set(coverage["unknown_tools"])),
            "unknown_tools": coverage["unknown_tools"],
            "registered_tool_rate": coverage["registered_rate"],
            "unknown_tool_rate": coverage["unknown_rate"],
            "error": error,
        }

    payload = {
        "benchmark_version": "v1.2.2",
        "suites": per_suite,
        "combined": taxonomy.coverage(sorted(all_tools)),
        "errors": errors,
        "acceptance": {
            "unknown_tool_rate_lte_0_05": all(item["unknown_tool_rate"] <= 0.05 for item in per_suite.values() if not item["error"])
        },
    }
    (REPORT_DIR / "tool_coverage.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = ["# AgentDojo Official Tool Inventory", ""]
    for suite_name, item in per_suite.items():
        lines.extend(
            [
                f"## {suite_name}",
                "",
                f"- official_tool_count: {item['official_tool_count']}",
                f"- registered_tools: {len(item['registered_tools'])}",
                f"- unknown_tools: {len(item['unknown_tools'])}",
                f"- registered_tool_rate: {item['registered_tool_rate']:.3f}",
                f"- unknown_tool_rate: {item['unknown_tool_rate']:.3f}",
                f"- error: {item['error'] or 'none'}",
                "",
                "### Unknown Tools",
                "",
                ", ".join(item["unknown_tools"]) if item["unknown_tools"] else "none",
                "",
                "### Official Tools",
                "",
                ", ".join(item["official_tools"]) if item["official_tools"] else "none",
                "",
            ]
        )
    (REPORT_DIR / "tool_inventory.md").write_text("\n".join(lines), encoding="utf-8")
    print(REPORT_DIR / "tool_inventory.md")


if __name__ == "__main__":
    main()



