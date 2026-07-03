"""Agent tool parser registry."""

from __future__ import annotations

from typing import Any

from .tool_mapping import ToolIntrospector, ToolMapping, ToolMappingRegistry
from .tool_parser import (
    AiderToolParser,
    AnthropicToolUseParser,
    ClineToolParser,
    GenericJSONToolParser,
    OpenAIToolParser,
    OpenClawToolParser,
    OpenHandsToolParser,
    ToolParser,
    ToolParseResult,
)


class ToolParserRegistry:
    def __init__(self, mapping_registry: ToolMappingRegistry | None = None) -> None:
        self._parsers: dict[str, ToolParser] = {
            "generic_json": GenericJSONToolParser(),
            "openai": OpenAIToolParser(),
            "codex": OpenAIToolParser(),
            "cline": ClineToolParser(),
            "cline_like": ClineToolParser(),
            "claude_code": AnthropicToolUseParser(),
            "anthropic": AnthropicToolUseParser(),
            "aider": AiderToolParser(),
            "openclaw": OpenClawToolParser(),
            "openhands": OpenHandsToolParser(),
        }
        self.default_agent = "generic_json"
        self.mapping_registry = mapping_registry or ToolMappingRegistry()

    def register(self, agent_type: str, parser: ToolParser) -> None:
        self._parsers[agent_type] = parser

    def register_tool_mapping(self, mapping: ToolMapping) -> None:
        self.mapping_registry.register(mapping)

    def register_tool_mappings(self, mappings: list[ToolMapping]) -> None:
        self.mapping_registry.register_many(mappings)

    def introspect_openai_tools(self, tools: list[dict[str, Any]], *, source: str = "openai_tools") -> list[ToolMapping]:
        mappings = ToolIntrospector().from_openai_tools(tools, source=source)
        self.register_tool_mappings(mappings)
        return mappings

    def introspect_mcp_manifest(self, manifest: dict[str, Any], *, source: str = "mcp_manifest") -> list[ToolMapping]:
        mappings = ToolIntrospector().from_mcp_manifest(manifest, source=source)
        self.register_tool_mappings(mappings)
        return mappings

    def introspect_agent_config(self, config: dict[str, Any], *, source: str = "agent_config") -> list[ToolMapping]:
        mappings = ToolIntrospector().from_agent_config(config, source=source)
        self.register_tool_mappings(mappings)
        return mappings

    def parse(self, tool_call: dict[str, Any], agent_type: str | None = None) -> ToolParseResult:
        mapped = self.mapping_registry.parse(tool_call)
        if mapped:
            return mapped
        parser = self._parsers.get(agent_type or self.default_agent) or self._parsers[self.default_agent]
        return parser.parse(tool_call)

    def agents(self) -> list[str]:
        return sorted(self._parsers)
