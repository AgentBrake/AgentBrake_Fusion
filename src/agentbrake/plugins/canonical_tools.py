"""Canonical agent tool names understood by agentbrake."""

from __future__ import annotations

CANONICAL_TOOLS = {
    "read_file",
    "write_file",
    "edit_file",
    "delete_file",
    "bash_exec",
    "git_op",
    "package_op",
    "network_op",
    "mcp_call",
    "memory_read",
    "memory_write",
    "browser_fetch",
    "github_api",
    "ci_cd_op",
    "publish_op",
    "unknown_side_effect",
}

TOOL_RISK_HINTS = {
    "read_file": "low",
    "write_file": "medium",
    "edit_file": "medium",
    "delete_file": "high",
    "bash_exec": "high",
    "git_op": "high",
    "package_op": "high",
    "network_op": "high",
    "mcp_call": "high",
    "memory_read": "medium",
    "memory_write": "high",
    "browser_fetch": "medium",
    "github_api": "high",
    "ci_cd_op": "high",
    "publish_op": "critical",
    "unknown_side_effect": "high",
}
