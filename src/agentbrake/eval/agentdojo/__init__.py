"""AgentDojo evaluation integration.

The recommended path is AgentDojo Tool Firewall under
``agentbrake.eval.agentdojo.gate``. Optional AgentDojo/OpenAI dependencies are
loaded only by runner and adapter entrypoints.
"""

from .evidence.state import AgentDojoStateTracker
from .evidence.taxonomy import AgentDojoToolTaxonomy
from .fact_adapter import agentdojo_facts_from_action
from .gate.tool_firewall import AgentDojoToolFirewall, ToolExecutionDecision, summarize_agentdojo_firewall_audit
from .tool_gate import AgentBrakeToolGate, ToolGateResult, taxonomy_coverage_summary
from .tool_taxonomy import AGENTDOJO_TOOL_TAXONOMY, classify_agentdojo_tool, coverage_report, load_agentdojo_taxonomy

__all__ = [
    "AGENTDOJO_TOOL_TAXONOMY",
    "AgentDojoToolFirewall",
    "AgentDojoToolTaxonomy",
    "AgentBrakeAgentDojoPipeline",
    "AgentBrakeToolGate",
    "ToolGateResult",
    "ToolExecutionDecision",
    "AgentDojoStateTracker",
    "agentdojo_facts_from_action",
    "build_agentbrake_agentdojo_pipeline",
    "classify_agentdojo_tool",
    "coverage_report",
    "load_agentdojo_taxonomy",
    "require_agentdojo",
    "summarize_agentdojo_firewall_audit",
    "summarize_agentdojo_audit",
    "taxonomy_coverage_summary",
]


def require_agentdojo() -> None:
    try:
        import agentdojo  # noqa: F401
    except ImportError as exc:
        raise RuntimeError("AgentDojo evaluation requires: pip install -e '.[agentdojo]'") from exc


def __getattr__(name: str):
    if name == "summarize_agentdojo_audit":
        from .runner.result_exporter import summarize_agentdojo_audit

        return summarize_agentdojo_audit
    if name in {"AgentBrakeToolGate", "ToolGateResult"}:
        from .tool_gate import AgentBrakeToolGate, ToolGateResult

        return {"AgentBrakeToolGate": AgentBrakeToolGate, "ToolGateResult": ToolGateResult}[name]
    if name in {"agentbrake_agentdojo", "register_native_defense"}:
        if name == "agentbrake_agentdojo":
            from .adapters.inspect_adapter import agentbrake_agentdojo

            return agentbrake_agentdojo
        from .adapters.native_defense import register_native_defense

        return register_native_defense
    if name in {"AgentBrakeAgentDojoPipeline", "build_agentbrake_agentdojo_pipeline"}:
        from .adapters.pipeline_wrapper import AgentBrakeAgentDojoPipeline, build_agentbrake_agentdojo_pipeline

        return {
            "AgentBrakeAgentDojoPipeline": AgentBrakeAgentDojoPipeline,
            "build_agentbrake_agentdojo_pipeline": build_agentbrake_agentdojo_pipeline,
        }[name]
    raise AttributeError(name)


def __dir__() -> list[str]:
    return sorted(
        set(globals())
        | {"AgentBrakeAgentDojoPipeline", "build_agentbrake_agentdojo_pipeline", "agentbrake_agentdojo", "register_native_defense"}
    )

