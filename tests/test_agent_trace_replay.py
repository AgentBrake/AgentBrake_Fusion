from __future__ import annotations

import json
from pathlib import Path

from agentbrake.instruction_ir import InstructionBuilder, InstructionLowerer
from agentbrake.plugins import ToolParserRegistry
from agentbrake.trace_matrix import run_trace_matrix

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "agent_traces"


def iter_trace_events():
    for trace_path in sorted(FIXTURE_DIR.glob("*.jsonl")):
        for line in trace_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                yield trace_path.name, json.loads(line)


def test_realistic_agent_trace_fixtures_replay_to_action_ir(tmp_path: Path):
    seen_agents: set[str] = set()
    lowerer = InstructionLowerer()

    for trace_name, event in iter_trace_events():
        assert event["event_type"] == "assistant_tool_call"
        seen_agents.add(event["agent_type"])

        builder = InstructionBuilder(trace_id=event["trace_id"], registry=ToolParserRegistry())
        instruction = builder.from_tool_call(
            event["tool_call"],
            turn_id=event["turn_id"],
            source_ids=event.get("source_ids", []),
            agent_type=event["agent_type"],
            trust_floor="untrusted",
        )
        action = lowerer.lower(instruction, cwd=tmp_path)

        assert action is not None, trace_name
        assert instruction.metadata["canonical_tool"] == event["expected"]["canonical_tool"]
        assert action.semantic_action == event["expected"]["semantic_action"]
        assert action.raw_action == event["expected"]["raw_action"]
        assert action.metadata["trace_id"] == event["trace_id"]

    assert seen_agents == {"aider", "cline_like", "openhands"}


def test_agent_trace_compatibility_matrix_report(tmp_path: Path):
    report = run_trace_matrix(FIXTURE_DIR, tmp_path / "matrix")
    assert report["metrics"]["trace_count"] == 3
    assert report["metrics"]["agent_count"] == 3
    assert report["metrics"]["pass_rate"] == 1.0
    assert (tmp_path / "matrix" / "trace_matrix_report.json").exists()
    assert (tmp_path / "matrix" / "trace_matrix_report.html").exists()
