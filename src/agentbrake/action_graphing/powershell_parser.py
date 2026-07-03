"""PowerShell parser for encoded and common web/file cmdlet patterns."""

from __future__ import annotations

import base64
import re

from ..models import ActionEdge, new_id
from .base import GraphBuildContext, GraphFragment
from .fallback_heuristic import FallbackHeuristicParser, _node, target_hint


class PowerShellParser:
    name = "powershell_parser"

    def can_parse(self, ctx: GraphBuildContext) -> bool:
        return bool(re.search(r"\b(?:powershell|pwsh|get-content|invoke-webrequest|invoke-restmethod)\b", ctx.action.raw_action, re.I))

    def parse(self, ctx: GraphBuildContext) -> GraphFragment:
        raw = ctx.action.raw_action
        decoded = _decode_encoded_command(raw)
        text = decoded or raw
        reads = re.findall(r"Get-Content\s+([^\s|;]+)", text, re.I)
        env_reads = re.findall(r"\$env:([A-Za-z_][A-Za-z0-9_]*)", text, re.I)
        writes = re.findall(r"(?:Out-File|Set-Content)\s+([^\s|;]+)", text, re.I)
        starts = re.findall(r"Start-Process\s+([^\s|;]+)", text, re.I)
        sinks = re.findall(r"https?://([^/\s'\")]+)", text, re.I)
        if re.search(r"\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b", text, re.I) and not sinks:
            target = target_hint(text, ctx.action.affected_assets)
            if target:
                sinks.append(target)
        nodes = []
        edges = []
        for idx, path in enumerate(reads):
            nodes.append(
                _node(
                    ctx.action,
                    new_id("anode"),
                    "read_secret_file" if ".env" in path.lower() else "read_file",
                    path.strip("'\""),
                    path,
                    idx,
                    self.name,
                )
            )
        for env in env_reads:
            nodes.append(_node(ctx.action, new_id("anode"), "read_secret_env", f"env:{env}", f"$env:{env}", len(nodes), self.name))
        for path in writes:
            nodes.append(_node(ctx.action, new_id("anode"), "edit_source_file", path.strip("'\""), path, len(nodes), self.name))
        for proc in starts:
            nodes.append(_node(ctx.action, new_id("anode"), "unknown_side_effect", proc.strip("'\""), proc, len(nodes), self.name))
        for sink in sinks:
            nodes.append(_node(ctx.action, new_id("anode"), "send_network_request", sink, sink, len(nodes), self.name))
        if not nodes:
            return FallbackHeuristicParser().parse(ctx)
        for src in [n for n in nodes if n.semantic_action in {"read_secret_file", "read_secret_env"}]:
            for dst in [n for n in nodes if n.semantic_action == "send_network_request"]:
                edges.append(
                    ActionEdge(
                        new_id("aedge"),
                        src.node_id,
                        dst.node_id,
                        "dataflow",
                        evidence_refs=[ctx.action.action_id],
                        confidence=0.8,
                        metadata={"parser": self.name, "decoded": decoded is not None},
                    )
                )
        for node in nodes:
            node.metadata["decoded"] = decoded is not None
        return GraphFragment(nodes, edges, 0.8, True, self.name)


def _decode_encoded_command(raw: str) -> str | None:
    m = re.search(r"-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]+)", raw, re.I)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16le", errors="replace")
    except Exception:
        return None
