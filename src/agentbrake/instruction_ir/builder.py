"""Build InstructionIR objects from OpenAI-compatible messages and tool calls."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ..models import TrustLevel, new_id
from ..plugins import ToolParserRegistry
from .schema import InstructionIR, SecurityType, new_instruction

TRUST_TO_SECURITY = {
    "admin": "HIGH",
    "trusted": "HIGH",
    "semi_trusted": "MEDIUM",
    "untrusted": "LOW",
    "tool_untrusted": "LOW",
    "tainted": "LOW",
    "unknown": "UNKNOWN",
}


class InstructionBuilder:
    def __init__(self, trace_id: str | None = None, registry: ToolParserRegistry | None = None) -> None:
        self.trace_id = trace_id or new_id("trace")
        self.registry = registry or ToolParserRegistry()
        self._step = 0

    def next_step(self) -> int:
        self._step += 1
        return self._step

    def from_message(
        self, message: dict[str, Any], *, turn_id: str, source_ids: list[str] | None = None, trust_floor: TrustLevel = "unknown"
    ) -> InstructionIR:
        role = str(message.get("role", "unknown"))
        content = message.get("content", "")
        security = self._security_for_sources(source_ids or [], trust_floor, risk="low" if role == "system" else "medium")
        kind = "plan" if role == "assistant" else "message"
        typ = "PLAN" if role == "assistant" else "UNKNOWN"
        return new_instruction(
            trace_id=self.trace_id,
            turn_id=turn_id,
            runtime_step=self.next_step(),
            kind=kind,
            raw={"role": role, "content": content},
            source_message_id=str(message.get("id") or f"msg_{role}_{self._step}"),
            source_ids=source_ids or [],
            instruction_type=typ,
            instruction_category=f"MESSAGE.{role}",
            security_type=security,
            metadata={"role": role},
        )

    def from_tool_call(
        self,
        tool_call: dict[str, Any],
        *,
        turn_id: str,
        source_ids: list[str] | None = None,
        parent_instruction_id: str | None = None,
        agent_type: str = "openai",
        trust_floor: TrustLevel = "unknown",
    ) -> InstructionIR:
        parsed = self.registry.parse(tool_call, agent_type=agent_type)
        security = self._security_for_sources(source_ids or [], trust_floor, risk=parsed.default_risk)
        return new_instruction(
            trace_id=self.trace_id,
            turn_id=turn_id,
            runtime_step=self.next_step(),
            kind="tool_call",
            raw={"tool_call": tool_call, "parsed": asdict(parsed)},
            source_message_id=str(tool_call.get("id") or f"tool_{self._step}"),
            parent_instruction_id=parent_instruction_id,
            source_ids=source_ids or [],
            instruction_type=parsed.instruction_type,  # type: ignore[arg-type]
            instruction_category=parsed.instruction_category,
            security_type=security,
            parser_confidence=parsed.parser_confidence,
            metadata={"canonical_tool": parsed.canonical_tool, "tool_name": parsed.tool_name, "tool_parse": asdict(parsed)},
        )

    def response_to_instructions(
        self,
        response_message: dict[str, Any],
        *,
        turn_id: str,
        source_ids: list[str] | None = None,
        agent_type: str = "openai",
        trust_floor: TrustLevel = "unknown",
    ) -> list[InstructionIR]:
        instructions: list[InstructionIR] = []
        parent = None
        if response_message.get("content"):
            plan = self.from_message(response_message, turn_id=turn_id, source_ids=source_ids, trust_floor=trust_floor)
            instructions.append(plan)
            parent = plan.instruction_id
        for tool_call in response_message.get("tool_calls", []) or []:
            instructions.append(
                self.from_tool_call(
                    tool_call,
                    turn_id=turn_id,
                    source_ids=source_ids,
                    parent_instruction_id=parent,
                    agent_type=agent_type,
                    trust_floor=trust_floor,
                )
            )
        return instructions

    @staticmethod
    def _security_for_sources(source_ids: list[str], trust_floor: TrustLevel, risk: str) -> SecurityType:
        tw = TRUST_TO_SECURITY.get(trust_floor, "UNKNOWN")
        if source_ids and trust_floor in {"untrusted", "tool_untrusted", "tainted", "unknown"}:
            tw = "LOW"
        confidentiality = "HIGH" if risk == "critical" else "MEDIUM" if risk == "high" else "LOW"
        return SecurityType(
            confidentiality=confidentiality,
            trustworthiness=tw,
            prop_confidentiality=confidentiality,
            prop_trustworthiness=tw,
            risk=risk,
            confidence="HIGH" if tw != "UNKNOWN" else "MEDIUM",
        )  # type: ignore[arg-type]
