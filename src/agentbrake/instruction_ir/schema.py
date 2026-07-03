"""InstructionIR schema for AgentBrake-Fusion Gateway.

InstructionIR is the runtime-governance layer between model messages/tool calls
and AgentBrake-Fusion's execution-facing ActionIR.  It records message lineage,
provenance, parser confidence and taint/security propagation so incident reports
can explain *why a model output became an executable action*.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from ..models import Risk, new_id, sha256_json, utc_now

InstructionKind = Literal["message", "plan", "tool_call", "tool_result", "confirmation"]
InstructionType = Literal["READ", "WRITE", "EXEC", "NETWORK", "MEMORY", "MCP", "PLAN", "UNKNOWN"]


@dataclass(slots=True)
class SecurityType:
    confidentiality: str = "LOW"
    trustworthiness: str = "UNKNOWN"
    prop_confidentiality: str = "LOW"
    prop_trustworthiness: str = "UNKNOWN"
    risk: Risk = "medium"
    confidence: str = "MEDIUM"


@dataclass(slots=True)
class InstructionIR:
    instruction_id: str
    trace_id: str
    turn_id: str
    runtime_step: int
    kind: InstructionKind
    raw: dict[str, Any]
    source_message_id: str | None = None
    parent_instruction_id: str | None = None
    reference_instruction_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    instruction_type: InstructionType = "UNKNOWN"
    instruction_category: str = "UNKNOWN"
    security_type: SecurityType = field(default_factory=SecurityType)
    lowered_action_ir_id: str | None = None
    parser_confidence: float = 1.0
    created_at: str = field(default_factory=utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def instruction_hash(self) -> str:
        return sha256_json(to_dict(self, include_hash=False))


def to_dict(instruction: InstructionIR | SecurityType, include_hash: bool = True) -> dict[str, Any]:
    data = asdict(instruction)
    if isinstance(instruction, InstructionIR) and include_hash:
        data["instruction_hash"] = instruction.instruction_hash
    return data


def new_instruction(
    *,
    trace_id: str,
    turn_id: str,
    runtime_step: int,
    kind: InstructionKind,
    raw: dict[str, Any],
    source_message_id: str | None = None,
    parent_instruction_id: str | None = None,
    reference_instruction_ids: list[str] | None = None,
    source_ids: list[str] | None = None,
    instruction_type: InstructionType = "UNKNOWN",
    instruction_category: str = "UNKNOWN",
    security_type: SecurityType | None = None,
    parser_confidence: float = 1.0,
    metadata: dict[str, Any] | None = None,
) -> InstructionIR:
    return InstructionIR(
        instruction_id=new_id("ins"),
        trace_id=trace_id,
        turn_id=turn_id,
        runtime_step=runtime_step,
        kind=kind,
        raw=raw,
        source_message_id=source_message_id,
        parent_instruction_id=parent_instruction_id,
        reference_instruction_ids=reference_instruction_ids or [],
        source_ids=source_ids or [],
        instruction_type=instruction_type,
        instruction_category=instruction_category,
        security_type=security_type or SecurityType(),
        parser_confidence=parser_confidence,
        metadata=metadata or {},
    )
