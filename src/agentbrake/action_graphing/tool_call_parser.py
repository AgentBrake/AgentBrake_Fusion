"""Tool-call and history dependency enrichment."""

from __future__ import annotations

from ..models import ActionEdge, ActionNode, new_id
from .base import GraphBuildContext, GraphFragment


def enrich_with_tool_dependencies(fragment: GraphFragment, ctx: GraphBuildContext) -> GraphFragment:
    _add_explicit_output_references(fragment, ctx)
    state = ctx.session_state
    if state is None or not state.confirmed_secret_taint:
        return fragment
    network_nodes = [node for node in fragment.nodes if node.semantic_action == "send_network_request"]
    if not network_nodes:
        return fragment
    history_node = ActionNode(
        new_id("anode"),
        ctx.action.action_id,
        "read_secret_file",
        ctx.action.tool,
        "history.secret_taint",
        list(state.touched_secret_assets or ["history.secret_taint"]),
        list(ctx.action.source_ids),
        False,
        0.55,
        metadata={
            "parser_name": "tool_call_dependency",
            "inferred": True,
            "state_hash": state.state_hash,
            "source": "persistent_session_state",
            "taint_confidence": "confirmed",
        },
    )
    fragment.nodes.insert(0, history_node)
    for node in network_nodes:
        fragment.edges.append(
            ActionEdge(
                new_id("aedge"),
                history_node.node_id,
                node.node_id,
                "memoryflow",
                evidence_refs=[state.session_state_id, ctx.action.action_id],
                confidence=0.55,
                metadata={
                    "parser": "tool_call_dependency",
                    "inferred": True,
                    "state_hash": state.state_hash,
                    "taint_confidence": "confirmed",
                },
            )
        )
    fragment.confidence = min(fragment.confidence, 0.55)
    return fragment


def _add_explicit_output_references(fragment: GraphFragment, ctx: GraphBuildContext) -> None:
    refs = _output_refs(ctx.action.metadata)
    if not refs:
        return
    network_nodes = [node for node in fragment.nodes if node.semantic_action == "send_network_request"]
    if not network_nodes:
        return
    secret_like = bool(ctx.action.metadata.get("output_secret_taint")) or any(
        "secret" in ref.lower() or ".env" in ref.lower() or "token" in ref.lower() for ref in refs
    )
    source_node = ActionNode(
        new_id("anode"),
        ctx.action.action_id,
        "read_secret_file" if secret_like else "read_project_file",
        ctx.action.tool,
        ",".join(refs),
        refs,
        list(ctx.action.source_ids),
        False,
        0.65 if secret_like else 0.5,
        metadata={
            "parser_name": "tool_call_dependency",
            "explicit_reference": True,
            "output_refs": refs,
            "inferred_secret": secret_like,
        },
    )
    fragment.nodes.insert(0, source_node)
    for node in network_nodes:
        fragment.edges.append(
            ActionEdge(
                new_id("aedge"),
                source_node.node_id,
                node.node_id,
                "memoryflow",
                evidence_refs=[ctx.action.action_id, *refs],
                confidence=0.65 if secret_like else 0.5,
                metadata={"parser": "tool_call_dependency", "explicit_reference": True, "output_refs": refs},
            )
        )
    fragment.confidence = min(fragment.confidence, 0.65 if secret_like else 0.5)


def _output_refs(metadata: dict) -> list[str]:
    refs: list[str] = []
    for key in ("consumes_output_ids", "output_source_ids", "references"):
        value = metadata.get(key)
        if isinstance(value, list):
            refs.extend(str(item) for item in value if item)
        elif value:
            refs.append(str(value))
    for key in ("body_ref", "input_ref", "output_source_id"):
        value = metadata.get(key)
        if value:
            refs.append(str(value))
    return list(dict.fromkeys(refs))
