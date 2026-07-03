"""Tool-call parser registry.

The registry lets a new agent adapter register only a parser/mapping for
its tool-call shape.  The rest of AgentBrake-Fusion consumes the returned canonical
ToolParseResult and then lowers it to ActionIR.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..models import Risk
from .canonical_tools import TOOL_RISK_HINTS


@dataclass(slots=True)
class ToolParseResult:
    tool_name: str
    canonical_tool: str
    instruction_type: str
    instruction_category: str
    raw_action: str
    tool: str = "Bash"
    operation: str | None = None
    file_path: str | None = None
    default_risk: Risk = "high"
    parser_confidence: float = 0.8
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolParser(Protocol):
    def parse(self, tool_call: dict[str, Any]) -> ToolParseResult: ...


def decode_openai_tool_call(tool_call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return function name and JSON-ish arguments from OpenAI-compatible tool_calls."""
    if "function" in tool_call:
        fn = tool_call.get("function") or {}
        name = str(fn.get("name", "unknown_tool"))
        args = fn.get("arguments", {})
    else:
        name = str(tool_call.get("name") or tool_call.get("tool_name") or tool_call.get("type") or "unknown_tool")
        args = tool_call.get("arguments", tool_call.get("args", tool_call.get("input", {})))
    if isinstance(args, str):
        try:
            args = json.loads(args) if args.strip() else {}
        except json.JSONDecodeError:
            args = {"raw": args}
    if not isinstance(args, dict):
        args = {"value": args}
    return name, args


class GenericJSONToolParser:
    """Conservative parser for OpenAI/Anthropic/Cline-like JSON tool calls."""

    def parse(self, tool_call: dict[str, Any]) -> ToolParseResult:
        name, args = decode_openai_tool_call(tool_call)
        low = name.lower().replace("-", "_")
        joined_args = " ".join(str(v) for v in args.values())

        if re.search(r"bash|shell|terminal|run_command|execute|exec", low) or (low == "run" and "command" in args):
            cmd = str(args.get("command") or args.get("cmd") or args.get("input") or args.get("raw") or joined_args)
            return ToolParseResult(
                name,
                "bash_exec",
                "EXEC",
                "EXECUTION.Env",
                cmd,
                "Bash",
                default_risk="high",
                parser_confidence=0.94,
                metadata={"args": args},
            )

        if re.search(r"read", low) and re.search(r"file|path", low):
            path = str(args.get("path") or args.get("file") or args.get("target") or joined_args)
            return ToolParseResult(
                name,
                "read_file",
                "READ",
                "FS.Read",
                path,
                "Read",
                operation="read",
                file_path=path,
                default_risk="low",
                parser_confidence=0.92,
                metadata={"args": args},
            )

        if re.search(r"write|create", low) and re.search(r"file|path", low):
            path = str(args.get("path") or args.get("file") or args.get("target") or joined_args)
            return ToolParseResult(
                name,
                "write_file",
                "WRITE",
                "FS.Write",
                path,
                "Write",
                operation="write",
                file_path=path,
                default_risk="medium",
                parser_confidence=0.9,
                metadata={"args": args},
            )

        if re.search(r"edit|patch", low) and re.search(r"file|path", low):
            path = str(args.get("path") or args.get("file") or args.get("target") or joined_args)
            return ToolParseResult(
                name,
                "edit_file",
                "WRITE",
                "FS.Edit",
                path,
                "Edit",
                operation="edit",
                file_path=path,
                default_risk="medium",
                parser_confidence=0.9,
                metadata={"args": args},
            )

        if re.search(r"delete|remove", low) and re.search(r"file|path", low):
            path = str(args.get("path") or args.get("file") or args.get("target") or joined_args)
            return ToolParseResult(
                name,
                "delete_file",
                "WRITE",
                "FS.Delete",
                path,
                "Delete",
                operation="delete",
                file_path=path,
                default_risk="high",
                parser_confidence=0.88,
                metadata={"args": args},
            )

        if re.search(r"mcp|deploy|publish|destroy", low):
            raw = f"{name}({json.dumps(args, ensure_ascii=False, sort_keys=True)})"
            risk = "critical" if re.search(r"deploy|publish|delete|destroy", low) else "high"
            return ToolParseResult(
                name, "mcp_call", "MCP", "TOOL.MCP", raw, "MCP", default_risk=risk, parser_confidence=0.86, metadata={"args": args}
            )

        if re.search(r"memory", low):
            raw = str(args.get("content") or args.get("query") or joined_args)
            canonical = "memory_write" if re.search(r"write|remember|store", low) else "memory_read"
            return ToolParseResult(
                name,
                canonical,
                "MEMORY",
                f"MEMORY.{canonical}",
                raw,
                "Memory",
                default_risk="high" if canonical == "memory_write" else "medium",
                parser_confidence=0.82,
                metadata={"args": args},
            )

        if re.search(r"browser|fetch|http|url", low):
            url = str(args.get("url") or args.get("target") or joined_args)
            return ToolParseResult(
                name,
                "network_op",
                "NETWORK",
                "NETWORK.Fetch",
                f"curl {url}",
                "Bash",
                default_risk="high",
                parser_confidence=0.82,
                metadata={"args": args},
            )

        raw = str(args.get("command") or args.get("cmd") or args.get("raw") or f"{name} {joined_args}".strip())
        return ToolParseResult(
            name,
            "unknown_side_effect",
            "UNKNOWN",
            "UNKNOWN.SideEffect",
            raw,
            "Bash",
            default_risk=TOOL_RISK_HINTS["unknown_side_effect"],
            parser_confidence=0.35,
            metadata={"args": args, "fallback": True},
        )


class OpenAIToolParser(GenericJSONToolParser):
    """Parser for OpenAI-compatible `tool_calls[].function` records."""


class AnthropicToolUseParser(GenericJSONToolParser):
    """Parser for Anthropic `tool_use` content blocks."""

    def parse(self, tool_call: dict[str, Any]) -> ToolParseResult:
        if tool_call.get("type") == "tool_use":
            tool_call = {"name": tool_call.get("name"), "input": tool_call.get("input") or {}}
        return super().parse(tool_call)


class ClineToolParser(GenericJSONToolParser):
    """Parser for Cline-like tool schemas."""

    def parse(self, tool_call: dict[str, Any]) -> ToolParseResult:
        if "toolName" in tool_call or "toolInput" in tool_call:
            tool_call = {"name": tool_call.get("toolName"), "input": tool_call.get("toolInput") or {}}
        return super().parse(tool_call)


class OpenHandsToolParser(GenericJSONToolParser):
    """Parser for OpenHands action records."""

    def parse(self, tool_call: dict[str, Any]) -> ToolParseResult:
        if "action" in tool_call and "arguments" not in tool_call:
            tool_call = {"name": tool_call.get("action"), "arguments": tool_call.get("args") or tool_call.get("input") or {}}
        return super().parse(tool_call)


class OpenClawToolParser(GenericJSONToolParser):
    """Parser for OpenClaw-style agent tool records.

    OpenClaw integrations are expected to work best through the
    OpenAI-compatible gateway, but this parser also accepts common direct
    adapter shapes so AgentBrake-Fusion can sit at the tool boundary when needed.
    """

    def parse(self, tool_call: dict[str, Any]) -> ToolParseResult:
        if "tool" in tool_call and "arguments" not in tool_call and "input" not in tool_call:
            tool_call = {"name": tool_call.get("tool"), "arguments": tool_call.get("params") or tool_call.get("args") or {}}
        if "function_call" in tool_call and "function" not in tool_call:
            fn = tool_call.get("function_call") or {}
            tool_call = {"name": fn.get("name"), "arguments": fn.get("arguments") or fn.get("params") or {}}
        return super().parse(tool_call)


class AiderToolParser(GenericJSONToolParser):
    """Parser for aider transcript-derived JSON action records."""
