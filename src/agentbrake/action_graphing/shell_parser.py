"""Best-effort shell parser for security-relevant flow."""

from __future__ import annotations

import re

from ..models import ActionEdge, new_id
from .base import GraphBuildContext, GraphFragment
from .fallback_heuristic import FallbackHeuristicParser, _node, edge_relation, semantic_hint, target_hint


class ShellParser:
    name = "shell_parser"

    def can_parse(self, ctx: GraphBuildContext) -> bool:
        raw = ctx.action.raw_action.strip()
        return (
            bool(raw)
            and ctx.action.tool.lower() in {"bash", "shell", "sh"}
            or any(tok in raw for tok in ("|", "&&", "||", ";", ">", "curl", "wget"))
        )

    def parse(self, ctx: GraphBuildContext) -> GraphFragment:
        raw = ctx.action.raw_action
        if _python_snippet(raw) or re.search(r"\b(?:powershell|pwsh)\b", raw, re.I):
            return FallbackHeuristicParser().parse(ctx)
        parts = [p.strip() for p in re.split(r"\s*(?:&&|\|\||\||;|>>|>|<)\s*", raw) if p.strip()]
        if not parts:
            parts = [raw]
        nodes = []
        edges = []
        for idx, part in enumerate(parts):
            node = _node(
                ctx.action,
                new_id("anode"),
                semantic_hint(part, ctx.action.semantic_action),
                target_hint(part, ctx.action.affected_assets),
                part,
                idx,
                self.name,
            )
            nodes.append(node)
            if idx > 0:
                rel = edge_relation(raw, idx)
                edges.append(
                    ActionEdge(
                        new_id("aedge"),
                        nodes[idx - 1].node_id,
                        node.node_id,
                        rel,
                        evidence_refs=[ctx.action.action_id],
                        confidence=0.9,
                        metadata={"parser": self.name},
                    )
                )
                if rel == "pipe":
                    edges.append(
                        ActionEdge(
                            new_id("aedge"),
                            nodes[idx - 1].node_id,
                            node.node_id,
                            "dataflow",
                            evidence_refs=[ctx.action.action_id],
                            confidence=0.9,
                            metadata={"parser": self.name, "derived_from": "pipe"},
                        )
                    )
        for src, dst in _command_substitutions(raw, ctx, len(nodes)):
            nodes.extend([src, dst])
            edges.append(
                ActionEdge(
                    new_id("aedge"),
                    src.node_id,
                    dst.node_id,
                    "dataflow",
                    evidence_refs=[ctx.action.action_id],
                    confidence=0.75,
                    metadata={"parser": self.name, "derived_from": "command_substitution"},
                )
            )
        return GraphFragment(nodes, edges, min(ctx.action.parser_confidence, 0.9), True, self.name)


def _python_snippet(raw: str) -> bool:
    return bool(re.search(r"\bpython(?:3)?\s+-c\b", raw, re.I))


def _command_substitutions(raw: str, ctx: GraphBuildContext, start_idx: int):
    pairs = []
    for idx, match in enumerate(re.finditer(r"(?:\$\((.*?)\)|`([^`]+)`)", raw, re.S)):
        inner = (match.group(1) or match.group(2) or "").strip()
        if not inner:
            continue
        source = _node(
            ctx.action,
            new_id("anode"),
            semantic_hint(inner, ctx.action.semantic_action),
            target_hint(inner, ctx.action.affected_assets),
            inner,
            start_idx + idx * 2,
            "shell_parser",
        )
        sink = _node(
            ctx.action,
            new_id("anode"),
            semantic_hint(raw.replace(match.group(0), ""), ctx.action.semantic_action),
            target_hint(raw, ctx.action.affected_assets),
            match.group(0),
            start_idx + idx * 2 + 1,
            "shell_parser",
        )
        pairs.append((source, sink))
    return pairs
