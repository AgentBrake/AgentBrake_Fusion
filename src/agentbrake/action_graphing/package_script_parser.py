"""ExecTrace and package lifecycle enrichment for ActionGraph."""

from __future__ import annotations

from ..models import ActionEdge, ActionNode, new_id
from .base import GraphBuildContext, GraphFragment


def enrich_with_exec_trace(fragment: GraphFragment, ctx: GraphBuildContext) -> GraphFragment:
    trace = ctx.exec_trace
    package_event = ctx.package_event
    if trace is None and package_event is None:
        return fragment
    nodes = list(fragment.nodes)
    edges = list(fragment.edges)
    anchor = nodes[0] if nodes else None
    script_nodes: list[ActionNode] = []
    scripts = list(dict.fromkeys([*(package_event.lifecycle_scripts if package_event else []), *(trace.package_scripts if trace else [])]))
    for script in scripts:
        evidence_ref = trace.exec_trace_id if trace else package_event.package_event_id if package_event else ctx.action.action_id
        node = ActionNode(
            new_id("anode"),
            ctx.action.action_id,
            "run_package_lifecycle_script",
            ctx.action.tool,
            str(script),
            [str(script)],
            list(ctx.action.source_ids),
            True,
            0.85,
            metadata={
                "observed": trace is not None,
                "evidence_ref": evidence_ref,
                "parser_name": "trace_enrichment",
                "package_event": package_event.package_event_id if package_event else None,
            },
        )
        nodes.append(node)
        script_nodes.append(node)
        if anchor:
            edges.append(
                ActionEdge(
                    new_id("aedge"),
                    anchor.node_id,
                    node.node_id,
                    "controlflow",
                    evidence_refs=[evidence_ref],
                    confidence=0.85,
                    metadata={"observed": trace is not None, "package_event": package_event.package_event_id if package_event else None},
                )
            )
    for attempt in trace.network_attempts if trace else []:
        host = str(attempt.get("host") or attempt.get("url") or attempt)
        node = ActionNode(
            new_id("anode"),
            ctx.action.action_id,
            "send_network_request",
            ctx.action.tool,
            host,
            [host],
            list(ctx.action.source_ids),
            True,
            0.9,
            metadata={"observed": True, "evidence_ref": trace.exec_trace_id, "parser_name": "trace_enrichment", "network_attempt": attempt},
        )
        nodes.append(node)
        for src in script_nodes or ([anchor] if anchor else []):
            if src:
                edges.append(
                    ActionEdge(
                        new_id("aedge"),
                        src.node_id,
                        node.node_id,
                        "dataflow",
                        evidence_refs=[trace.exec_trace_id],
                        confidence=0.8,
                        metadata={"observed": True},
                    )
                )
    for env in trace.env_access if trace else []:
        node = ActionNode(
            new_id("anode"),
            ctx.action.action_id,
            "read_secret_env",
            ctx.action.tool,
            str(env),
            [f"env:{env}"],
            list(ctx.action.source_ids),
            False,
            0.85,
            metadata={"observed": True, "evidence_ref": trace.exec_trace_id, "parser_name": "trace_enrichment"},
        )
        nodes.append(node)
        for dst in [n for n in nodes if n.semantic_action == "send_network_request"]:
            edges.append(
                ActionEdge(
                    new_id("aedge"),
                    node.node_id,
                    dst.node_id,
                    "dataflow",
                    evidence_refs=[trace.exec_trace_id],
                    confidence=0.75,
                    metadata={"observed": True},
                )
            )
    fragment.nodes = nodes
    fragment.edges = edges
    fragment.parser_name = f"{fragment.parser_name}+trace"
    fragment.confidence = min(fragment.confidence, 0.85)
    return fragment
