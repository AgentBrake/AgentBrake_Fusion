"""Response transformation after policy decisions."""

from __future__ import annotations

from typing import Any

from .openai_compat import assistant_message_response, safe_block_message, safe_sandbox_only_message


def transform_response(
    original_message: dict[str, Any],
    guarded_results: list[dict[str, Any]],
    trace_id: str,
    model: str = "AgentBrake-Fusion/local",
    release_mode: str = "gateway_only",
) -> dict[str, Any]:
    blocked = [
        r
        for r in guarded_results
        if r.get("runtime", {}).get("effective_decision") in {"block", "quarantine", "require_confirmation", "sandbox_then_approval"}
    ]
    if blocked:
        message = safe_block_message("AgentBrake-Fusion 网关策略结果：", blocked, trace_id)
        return assistant_message_response(message, model=model)
    sandbox_only = [r for r in guarded_results if r.get("runtime", {}).get("effective_decision") == "allow_in_sandbox"]
    if sandbox_only and release_mode != "gateway_plus_guarded_tools":
        message = safe_sandbox_only_message("AgentBrake-Fusion 网关沙箱约束结果：", sandbox_only, trace_id)
        return assistant_message_response(message, model=model)
    # Only unconstrained allow actions can be released as tool calls.
    return assistant_message_response(original_message, model=model)
