"""Tool introspection and dynamic mapping for agent tool schemas."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..models import Risk
from .canonical_tools import CANONICAL_TOOLS, TOOL_RISK_HINTS
from .tool_parser import ToolParseResult, decode_openai_tool_call


@dataclass(slots=True)
class ToolMapping:
    tool_name: str
    canonical_tool: str
    raw_action_arg: str | None = None
    file_path_arg: str | None = None
    operation: str | None = None
    default_risk: Risk = "high"
    confidence: float = 0.65
    source: str = "introspection"
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolMappingRegistry:
    """Runtime registry of introspected tool mappings."""

    def __init__(self, mappings: list[ToolMapping] | None = None) -> None:
        self._mappings: dict[str, ToolMapping] = {}
        for mapping in mappings or []:
            self.register(mapping)

    def register(self, mapping: ToolMapping) -> None:
        self._mappings[_norm(mapping.tool_name)] = mapping

    def register_many(self, mappings: list[ToolMapping]) -> None:
        for mapping in mappings:
            self.register(mapping)

    def get(self, tool_name: str) -> ToolMapping | None:
        return self._mappings.get(_norm(tool_name))

    def parse(self, tool_call: dict[str, Any]) -> ToolParseResult | None:
        name, args = _decode_tool_call(tool_call)
        mapping = self.get(name)
        if not mapping:
            return None
        raw_action = _raw_action(mapping, name, args)
        return ToolParseResult(
            tool_name=name,
            canonical_tool=mapping.canonical_tool,
            instruction_type=_instruction_type(mapping.canonical_tool),
            instruction_category=_instruction_category(mapping.canonical_tool),
            raw_action=raw_action,
            tool=_tool_label(mapping.canonical_tool),
            operation=mapping.operation,
            file_path=_arg_value(args, mapping.file_path_arg),
            default_risk=mapping.default_risk,
            parser_confidence=mapping.confidence,
            metadata={"args": args, "mapping": _mapping_dict(mapping)},
        )

    def mappings(self) -> list[ToolMapping]:
        return [self._mappings[name] for name in sorted(self._mappings)]


class ToolIntrospector:
    """Infer AgentBrake-Fusion tool mappings from common tool definition formats."""

    def from_openai_tools(self, tools: list[dict[str, Any]], *, source: str = "openai_tools") -> list[ToolMapping]:
        mappings: list[ToolMapping] = []
        for tool in tools:
            fn = tool.get("function") if tool.get("type") == "function" else tool
            if not isinstance(fn, dict):
                continue
            name = str(fn.get("name") or "")
            if not name:
                continue
            schema = fn.get("parameters") or fn.get("input_schema") or {}
            mappings.append(self.from_json_schema(name, schema, description=str(fn.get("description") or ""), source=source))
        return mappings

    def from_mcp_manifest(self, manifest: dict[str, Any], *, source: str = "mcp_manifest") -> list[ToolMapping]:
        mappings: list[ToolMapping] = []
        tools = manifest.get("tools") or manifest.get("declared_tools") or []
        capabilities = manifest.get("declared_capabilities") or manifest.get("capabilities") or []
        if isinstance(tools, dict):
            tools = [{"name": name, **(spec if isinstance(spec, dict) else {})} for name, spec in tools.items()]
        for index, tool in enumerate(tools):
            if isinstance(tool, str):
                desc = " ".join(str(c) for c in capabilities)
                mappings.append(self.infer(tool, description=desc, schema={}, source=source, metadata={"mcp": True}))
                continue
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name") or tool.get("tool") or "")
            if not name:
                continue
            schema = tool.get("inputSchema") or tool.get("input_schema") or tool.get("parameters") or {}
            desc = str(tool.get("description") or (capabilities[index] if index < len(capabilities) else ""))
            mappings.append(self.infer(name, description=desc, schema=schema, source=source, metadata={"mcp": True}))
        return mappings

    def from_agent_config(self, config: dict[str, Any], *, source: str = "agent_config") -> list[ToolMapping]:
        tools = config.get("tools") or config.get("tool_registry") or config.get("available_tools") or []
        if isinstance(tools, dict):
            tools = [{"name": name, **(spec if isinstance(spec, dict) else {})} for name, spec in tools.items()]
        mappings: list[ToolMapping] = []
        for tool in tools:
            if isinstance(tool, str):
                mappings.append(self.infer(tool, source=source))
                continue
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name") or tool.get("tool") or tool.get("id") or "")
            if not name:
                continue
            schema = tool.get("schema") or tool.get("parameters") or tool.get("input_schema") or tool.get("inputSchema") or {}
            mappings.append(
                self.infer(
                    name, description=str(tool.get("description") or ""), schema=schema, source=source, metadata={"agent_config": True}
                )
            )
        return mappings

    def from_json_schema(self, name: str, schema: dict[str, Any], *, description: str = "", source: str = "json_schema") -> ToolMapping:
        return self.infer(name, description=description, schema=schema, source=source)

    def infer(
        self,
        name: str,
        *,
        description: str = "",
        schema: dict[str, Any] | None = None,
        source: str = "introspection",
        metadata: dict[str, Any] | None = None,
    ) -> ToolMapping:
        schema = schema or {}
        props = _schema_properties(schema)
        canonical, confidence = _infer_canonical(name, description, props)
        raw_arg = _choose_arg(props, ["command", "cmd", "shell", "query", "url", "path", "file", "content", "input"])
        path_arg = _choose_arg(props, ["path", "file_path", "filepath", "filename", "file", "target"])
        operation = _operation_for(canonical)
        if canonical == "bash_exec":
            raw_arg = _choose_arg(props, ["command", "cmd", "shell", "input"]) or raw_arg
        elif canonical in {"read_file", "write_file", "edit_file", "delete_file"}:
            raw_arg = path_arg or raw_arg
        elif canonical in {"network_op", "browser_fetch"}:
            raw_arg = _choose_arg(props, ["url", "uri", "target", "endpoint", "query"]) or raw_arg
        if canonical == "mcp_call":
            confidence = min(confidence, 0.78)
        risk = TOOL_RISK_HINTS.get(canonical, TOOL_RISK_HINTS["unknown_side_effect"])  # type: ignore[assignment]
        return ToolMapping(
            tool_name=name,
            canonical_tool=canonical,
            raw_action_arg=raw_arg,
            file_path_arg=path_arg,
            operation=operation,
            default_risk=risk,  # type: ignore[arg-type]
            confidence=confidence,
            source=source,
            description=description,
            metadata={"properties": sorted(props), **(metadata or {})},
        )


def _norm(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _decode_tool_call(tool_call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if "tool" in tool_call and "function" not in tool_call:
        name = str(tool_call.get("tool") or "unknown_tool")
        args = tool_call.get("params", tool_call.get("args", tool_call.get("input", {})))
    elif "function_call" in tool_call and "function" not in tool_call:
        fn = tool_call.get("function_call") or {}
        name = str(fn.get("name") or "unknown_tool")
        args = fn.get("arguments", fn.get("params", {}))
    else:
        name, args = decode_openai_tool_call(tool_call)
    if isinstance(args, str):
        try:
            args = json.loads(args) if args.strip() else {}
        except json.JSONDecodeError:
            args = {"raw": args}
    if not isinstance(args, dict):
        args = {"value": args}
    return name, args


def _schema_properties(schema: dict[str, Any]) -> dict[str, Any]:
    props = schema.get("properties") if isinstance(schema, dict) else {}
    return props if isinstance(props, dict) else {}


def _infer_canonical(name: str, description: str, props: dict[str, Any]) -> tuple[str, float]:
    text = " ".join([name, description, " ".join(props)]).lower().replace("-", "_")
    if re.search(r"bash|shell|terminal|run_command|execute_command|exec|command", text):
        return "bash_exec", 0.88
    if re.search(r"delete|remove|unlink", text) and re.search(r"file|path", text):
        return "delete_file", 0.84
    if re.search(r"edit|patch|replace|modify", text) and re.search(r"file|path|content", text):
        return "edit_file", 0.84
    if re.search(r"write|create|save", text) and re.search(r"file|path|content", text):
        return "write_file", 0.83
    if re.search(r"read|open|load", text) and re.search(r"file|path", text):
        return "read_file", 0.86
    if re.search(r"deploy|publish|release", text):
        return "publish_op", 0.82
    if re.search(r"github|gitlab|pull_request|issue|repo_api", text):
        return "github_api", 0.76
    if re.search(r"memory|remember|store_context", text):
        return ("memory_write", 0.78) if re.search(r"write|remember|store", text) else ("memory_read", 0.72)
    if re.search(r"browser|fetch|http|url|request|web", text):
        return "network_op", 0.78
    if re.search(r"mcp|tool", text):
        return "mcp_call", 0.7
    return "unknown_side_effect", 0.38


def _choose_arg(props: dict[str, Any], candidates: list[str]) -> str | None:
    normalized = {_norm(k): k for k in props}
    for candidate in candidates:
        if candidate in normalized:
            return normalized[candidate]
    for key in props:
        low = _norm(key)
        if any(candidate in low for candidate in candidates):
            return key
    return None


def _operation_for(canonical: str) -> str | None:
    return {
        "read_file": "read",
        "write_file": "write",
        "edit_file": "edit",
        "delete_file": "delete",
    }.get(canonical)


def _arg_value(args: dict[str, Any], key: str | None) -> str | None:
    if not key:
        return None
    value = args.get(key)
    return None if value is None else str(value)


def _raw_action(mapping: ToolMapping, name: str, args: dict[str, Any]) -> str:
    value = _arg_value(args, mapping.raw_action_arg)
    if value:
        return value
    if mapping.canonical_tool == "mcp_call":
        return f"{name}({json.dumps(args, ensure_ascii=False, sort_keys=True)})"
    if mapping.canonical_tool in CANONICAL_TOOLS:
        joined = " ".join(str(v) for v in args.values())
        return joined or name
    return f"{name} {json.dumps(args, ensure_ascii=False, sort_keys=True)}".strip()


def _instruction_type(canonical: str) -> str:
    if canonical in {"read_file"}:
        return "READ"
    if canonical in {"write_file", "edit_file", "delete_file"}:
        return "WRITE"
    if canonical in {"mcp_call"}:
        return "MCP"
    if canonical in {"memory_read", "memory_write"}:
        return "MEMORY"
    if canonical in {"network_op", "browser_fetch"}:
        return "NETWORK"
    return "EXEC" if canonical != "unknown_side_effect" else "UNKNOWN"


def _instruction_category(canonical: str) -> str:
    return {
        "read_file": "FS.Read",
        "write_file": "FS.Write",
        "edit_file": "FS.Edit",
        "delete_file": "FS.Delete",
        "mcp_call": "TOOL.MCP",
        "memory_read": "MEMORY.memory_read",
        "memory_write": "MEMORY.memory_write",
        "network_op": "NETWORK.Fetch",
        "browser_fetch": "NETWORK.Browser",
    }.get(canonical, "EXECUTION.Env" if canonical != "unknown_side_effect" else "UNKNOWN.SideEffect")


def _tool_label(canonical: str) -> str:
    if canonical in {"read_file"}:
        return "Read"
    if canonical in {"write_file"}:
        return "Write"
    if canonical in {"edit_file"}:
        return "Edit"
    if canonical in {"delete_file"}:
        return "Delete"
    if canonical == "mcp_call":
        return "MCP"
    if canonical.startswith("memory_"):
        return "Memory"
    return "Bash"


def _mapping_dict(mapping: ToolMapping) -> dict[str, Any]:
    return {
        "tool_name": mapping.tool_name,
        "canonical_tool": mapping.canonical_tool,
        "raw_action_arg": mapping.raw_action_arg,
        "file_path_arg": mapping.file_path_arg,
        "operation": mapping.operation,
        "default_risk": mapping.default_risk,
        "confidence": mapping.confidence,
        "source": mapping.source,
        "description": mapping.description,
        "metadata": mapping.metadata,
    }
