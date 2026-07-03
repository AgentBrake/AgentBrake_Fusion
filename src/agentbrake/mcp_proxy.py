"""MCP/plugin zero-trust proxy MVP."""

from __future__ import annotations

import re

from .context import ContextProvenance
from .models import MCPInvocation, MCPServerManifest, new_id, sha256_json

TOKEN_PAT = re.compile(r"(Authorization\s*:\s*Bearer|access_token|refresh_token|client_token|ghp_|npm_)", re.I)
DESTRUCTIVE_CAPS = {"write", "delete", "external_write", "auth", "deploy", "publish", "memory_write"}


class MCPProxy:
    def __init__(self, provenance: ContextProvenance):
        self.provenance = provenance
        self.servers: dict[str, MCPServerManifest] = {}

    def register_server(self, manifest: MCPServerManifest) -> None:
        self.servers[manifest.mcp_server_id] = manifest

    def invoke(self, server_id: str, tool_name: str, args: dict, output: str = "") -> MCPInvocation:
        manifest = self.servers.get(server_id)
        if not manifest:
            return MCPInvocation(new_id("mcp"), server_id, tool_name, sha256_json(args), "unknown", "unknown", "blocked", ["unknown_tool"])
        declared = self._capability_for_tool(manifest, tool_name)
        observed = declared
        reasons: list[str] = []
        decision = "allowed"
        if TOKEN_PAT.search(str(args)):
            reasons.append("mcp_token_passthrough_attempt")
            decision = "blocked"
        if declared in DESTRUCTIVE_CAPS:
            reasons.append("destructive_tool_requires_approval")
            decision = "approval_required" if decision != "blocked" else decision
        source_id = None
        if output:
            src = self.provenance.ingest("mcp_output", output, retrieval_path=f"mcp:{server_id}.{tool_name}")
            source_id = src.source_id
        return MCPInvocation(
            invocation_id=new_id("mcp"),
            server_id=server_id,
            tool_name=tool_name,
            args_hash=sha256_json(args),
            declared_capability=declared,
            observed_capability=observed,
            decision=decision,
            reason_codes=reasons or ["mcp_output_downgraded_to_data"],
            output_source_id=source_id,
        )

    @staticmethod
    def _capability_for_tool(manifest: MCPServerManifest, tool_name: str) -> str:
        low = tool_name.lower()
        for cap in manifest.declared_capabilities:
            if cap in low:
                return cap
        if any(w in low for w in ["deploy", "publish"]):
            return "deploy"
        if any(w in low for w in ["delete", "remove"]):
            return "delete"
        if any(w in low for w in ["create", "write", "update"]):
            return "write"
        return "read"
