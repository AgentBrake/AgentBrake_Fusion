"""ActionGraph parser orchestration."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from ..models import ActionGraph, ActionIR, ExecTrace, PackageEvent, SessionState, sha256_text
from .base import GraphBuildContext
from .fallback_heuristic import PARSER_VERSION, FallbackHeuristicParser, graph_from_dict
from .package_script_parser import enrich_with_exec_trace
from .powershell_parser import PowerShellParser
from .python_snippet_parser import PythonSnippetParser
from .shell_ast_parser import ShellAstParser
from .shell_parser import ShellParser
from .tool_call_parser import enrich_with_tool_dependencies


def ensure_action_graph(
    action: ActionIR,
    *,
    run_id: str = "run_default",
    repo_root: str | Path | None = None,
    exec_trace: ExecTrace | None = None,
    package_event: PackageEvent | None = None,
    session_state: SessionState | None = None,
    parser_mode: str = "auto",
) -> ActionGraph:
    existing = action.metadata.get("action_graph")
    if (
        isinstance(existing, dict)
        and existing.get("graph_id")
        and str(existing.get("run_id") or "") == run_id
        and exec_trace is None
        and parser_mode == "auto"
        and session_state is None
    ):
        action.graph_id = str(existing["graph_id"])
        return graph_from_dict(existing)
    graph = build_action_graph(
        action,
        run_id=run_id,
        repo_root=repo_root,
        exec_trace=exec_trace,
        package_event=package_event,
        session_state=session_state,
        parser_mode=parser_mode,
    )
    action.graph_id = graph.graph_id
    action.metadata["action_graph_id"] = graph.graph_id
    action.metadata["action_graph"] = asdict(graph)
    return graph


def build_action_graph(
    action: ActionIR,
    *,
    run_id: str = "run_default",
    repo_root: str | Path | None = None,
    exec_trace: ExecTrace | None = None,
    package_event: PackageEvent | None = None,
    session_state: SessionState | None = None,
    parser_mode: str = "auto",
) -> ActionGraph:
    ctx = GraphBuildContext(
        action=action,
        run_id=run_id,
        repo_root=Path(repo_root).resolve() if repo_root else None,
        exec_trace=exec_trace,
        package_event=package_event,
        session_state=session_state,
    )
    parsers = [PowerShellParser(), PythonSnippetParser(), ShellAstParser(), ShellParser(), FallbackHeuristicParser()]
    fragment = None
    warnings: list[str] = []
    for parser in parsers:
        if parser_mode not in {"auto", parser.name, "fallback"} and parser.name != "fallback_heuristic":
            continue
        if parser_mode == "fallback" and parser.name != "fallback_heuristic":
            continue
        try:
            if parser.can_parse(ctx):
                fragment = parser.parse(ctx)
                break
        except Exception as exc:
            warnings.append(f"{parser.name}: {type(exc).__name__}")
            continue
    if fragment is None:
        fragment = FallbackHeuristicParser().parse(ctx)
    fragment = enrich_with_tool_dependencies(fragment, ctx)
    if package_event is not None or exec_trace is not None:
        fragment = enrich_with_exec_trace(fragment, ctx)
    graph = ActionGraph(
        graph_id=action.metadata.get("action_graph_id") or fragment.nodes[0].metadata.get("graph_id") if fragment.nodes else "",
        run_id=run_id,
        root_action_id=action.action_id,
        raw_action_hash=sha256_text(action.raw_action),
        nodes=fragment.nodes,
        edges=fragment.edges,
        parser_version=PARSER_VERSION,
        complete=fragment.complete and not warnings,
        metadata={
            "raw_action": action.raw_action,
            "compound": len(fragment.nodes) > 1,
            "parser": fragment.parser_name,
            "confidence": fragment.confidence,
            "warnings": [*fragment.warnings, *warnings],
            "trace_enriched": exec_trace is not None,
            "package_event_enriched": package_event is not None,
        },
    )
    if not graph.graph_id:
        from ..models import new_id

        graph.graph_id = new_id("agraph")
    for node in graph.nodes:
        node.metadata.setdefault("parser_name", fragment.parser_name)
    return graph
