"""Legacy-compatible ActionGraph heuristics."""

from __future__ import annotations

import re

from ..models import ActionEdge, ActionGraph, ActionIR, ActionNode, new_id
from .base import GraphBuildContext, GraphFragment

PARSER_VERSION = "action-graph-v2"


class FallbackHeuristicParser:
    name = "fallback_heuristic"

    def can_parse(self, _ctx: GraphBuildContext) -> bool:
        return True

    def parse(self, ctx: GraphBuildContext) -> GraphFragment:
        action = ctx.action
        parts = action.command_parts or _split_command(action.raw_action) or [action.raw_action]
        nodes: list[ActionNode] = []
        edges: list[ActionEdge] = []
        for idx, part in enumerate(parts):
            node_id = new_id("anode")
            semantic = action.semantic_action if len(parts) == 1 else semantic_hint(part, action.semantic_action)
            nodes.append(_node(action, node_id, semantic, target_hint(part, action.affected_assets), part, idx, "fallback_heuristic"))
        if idx > 0:
            relation = edge_relation(action.raw_action, idx)
            edges.append(
                ActionEdge(
                    new_id("aedge"),
                    nodes[idx - 1].node_id,
                    node_id,
                    relation,
                    evidence_refs=[action.action_id],
                    metadata={"separator_index": idx - 1},
                )
            )
            if relation == "pipe":
                edges.append(
                    ActionEdge(
                        new_id("aedge"),
                        nodes[idx - 1].node_id,
                        node_id,
                        "dataflow",
                        evidence_refs=[action.action_id],
                        confidence=0.9,
                        metadata={"separator_index": idx - 1, "derived_from": "pipe"},
                    )
                )
        if len(nodes) == 1 and looks_like_pipe(action.raw_action):
            nodes[0].metadata["pipe_like"] = True
        return GraphFragment(nodes, edges, action.parser_confidence, True, self.name)


def graph_from_dict(data: dict) -> ActionGraph:
    return ActionGraph(
        graph_id=str(data["graph_id"]),
        run_id=str(data.get("run_id") or "run_default"),
        root_action_id=str(data.get("root_action_id") or ""),
        raw_action_hash=str(data.get("raw_action_hash") or ""),
        nodes=[ActionNode(**node) for node in data.get("nodes", [])],
        edges=[ActionEdge(**edge) for edge in data.get("edges", [])],
        parser_version=str(data.get("parser_version") or PARSER_VERSION),
        complete=bool(data.get("complete", True)),
        metadata=dict(data.get("metadata") or {}),
    )


def _node(
    action: ActionIR, node_id: str, semantic_action: str, target: str | None, raw_part: str, part_index: int, parser_name: str
) -> ActionNode:
    affected = list(action.affected_assets)
    if target and target not in affected and (semantic_action in {"read_secret_file", "send_network_request"} or "." in target):
        affected.append(target)
    return ActionNode(
        node_id=node_id,
        action_id=action.action_id,
        semantic_action=semantic_action,
        tool=action.tool,
        target=target,
        affected_assets=affected,
        source_ids=list(action.source_ids),
        side_effect=action.side_effect or has_side_effect(raw_part),
        confidence=action.parser_confidence,
        metadata={"raw_part": raw_part, "part_index": part_index, "parser_name": parser_name},
    )


def _split_command(raw: str) -> list[str]:
    return [p.strip() for p in re.split(r"\s*(?:&&|\|\||\||;|>>|>)\s*", raw) if p.strip()]


def edge_relation(raw: str, idx: int) -> str:
    separators = re.findall(r"&&|\|\||\||;|>>|>", raw)
    sep = separators[idx - 1] if idx - 1 < len(separators) else ";"
    if sep == "|":
        return "pipe"
    if sep in {">", ">>"}:
        return "redirect"
    if sep in {"&&", "||"}:
        return "controlflow"
    return "sequence"


def looks_like_pipe(raw: str) -> bool:
    return "|" in raw or ">" in raw


def semantic_hint(part: str, fallback: str) -> str:
    low = part.lower()
    if any(
        token in low for token in ("curl", "wget", "invoke-webrequest", "invoke-restmethod", "http://", "https://", "requests.", "urlopen")
    ):
        return "send_network_request"
    if any(token in low for token in (".env", "secret", "get-content", "open(", "read_text", "os.environ", "os.getenv")):
        return "read_secret_file"
    if "base64" in low or "convertto-" in low:
        return "transform_data"
    if "npm install" in low or "pip install" in low:
        return "install_registry_dependency"
    if "npm test" in low or "pytest" in low:
        return "run_tests"
    return fallback


def target_hint(part: str, fallback_assets: list[str]) -> str | None:
    host = re.search(r"https?://([^/\s'\")]+)", part, re.I)
    if host:
        return host.group(1)
    env_path = re.search(r"(\.env[\w.-]*)", part)
    if env_path:
        return env_path.group(1)
    path = re.search(r"(\.github/workflows/[^\s'\"`|;]+|[A-Za-z0-9_./-]+\.(?:js|py|yml|yaml|json))", part)
    if path:
        return path.group(1)
    return fallback_assets[0] if fallback_assets else None


def has_side_effect(part: str) -> bool:
    return bool(
        re.search(
            r"\b(curl|wget|invoke-webrequest|invoke-restmethod|npm install|pip install|rm|mv|cp|echo|tee|sed -i|publish|requests\.)\b|>|>>",
            part,
            re.I,
        )
    )
