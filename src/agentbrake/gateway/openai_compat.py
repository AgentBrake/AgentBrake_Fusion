"""OpenAI-compatible request/response helpers."""

from __future__ import annotations

import json
import re
from typing import Any

from ..models import new_id, utc_now


def extract_messages(request: dict[str, Any]) -> list[dict[str, Any]]:
    if "messages" in request and isinstance(request["messages"], list):
        return request["messages"]
    if "input" in request:
        inp = request["input"]
        if isinstance(inp, str):
            return [{"role": "user", "content": inp}]
        if isinstance(inp, list):
            return inp
    return []


def latest_user_text(messages: list[dict[str, Any]]) -> str:
    for msg in reversed(messages):
        if msg.get("role") == "user":
            return str(msg.get("content") or "")
    return "general code maintenance task"


def assistant_message_response(message: dict[str, Any], model: str = "AgentBrake-Fusion/local") -> dict[str, Any]:
    return {
        "id": new_id("chatcmpl"),
        "object": "chat.completion",
        "created": utc_now(),
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if message.get("tool_calls") else "stop"}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def responses_api_response(chat_response: dict[str, Any], trace_id: str) -> dict[str, Any]:
    """Convert an internal chat-completions response into a minimal Responses API shape."""
    choice = (chat_response.get("choices") or [{}])[0] if isinstance(chat_response.get("choices"), list) else {}
    message = choice.get("message") or {}
    output: list[dict[str, Any]] = []
    content = message.get("content")
    if content:
        output.append(
            {
                "id": new_id("msg"),
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": str(content)}],
            }
        )
    for call in message.get("tool_calls") or []:
        function = call.get("function") or {}
        output.append(
            {
                "id": call.get("id") or new_id("call"),
                "type": "function_call",
                "name": function.get("name", "unknown_tool"),
                "arguments": function.get("arguments", "{}"),
                "call_id": call.get("id") or new_id("call"),
            }
        )
    usage = chat_response.get("usage") if isinstance(chat_response.get("usage"), dict) else {}
    input_tokens = int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0)
    output_tokens = int(usage.get("output_tokens") or usage.get("completion_tokens") or 0)
    return {
        "id": str(chat_response.get("id") or new_id("resp")),
        "object": "response",
        "created_at": chat_response.get("created") or utc_now(),
        "model": chat_response.get("model", "AgentBrake-Fusion/local"),
        "output": output,
        "metadata": {"agentbrake_trace_id": trace_id},
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens, "total_tokens": input_tokens + output_tokens},
    }


def responses_api_stream_events(response: dict[str, Any]) -> list[bytes]:
    """Encode a minimal Responses API response as SSE events."""
    response_id = str(response.get("id") or new_id("resp"))
    created_at = response.get("created_at") or utc_now()
    model = str(response.get("model") or "AgentBrake-Fusion/local")
    completed_response = {
        **response,
        "id": response_id,
        "object": "response",
        "created_at": created_at,
        "model": model,
        "status": "completed",
    }
    events: list[tuple[str, dict[str, Any]]] = [
        (
            "response.created",
            {
                "type": "response.created",
                "response": {
                    "id": response_id,
                    "object": "response",
                    "created_at": created_at,
                    "model": model,
                    "status": "in_progress",
                    "output": [],
                },
            },
        )
    ]
    for output_index, item in enumerate(response.get("output") or []):
        item_id = str(item.get("id") or new_id("item"))
        item = {**item, "id": item_id}
        events.append(
            (
                "response.output_item.added",
                {"type": "response.output_item.added", "output_index": output_index, "item": item},
            )
        )
        if item.get("type") == "message":
            for content_index, part in enumerate(item.get("content") or []):
                text = str(part.get("text") or "")
                content_part = {"type": "output_text", "text": ""}
                events.append(
                    (
                        "response.content_part.added",
                        {
                            "type": "response.content_part.added",
                            "item_id": item_id,
                            "output_index": output_index,
                            "content_index": content_index,
                            "part": content_part,
                        },
                    )
                )
                for chunk in _content_chunks(text):
                    events.append(
                        (
                            "response.output_text.delta",
                            {
                                "type": "response.output_text.delta",
                                "item_id": item_id,
                                "output_index": output_index,
                                "content_index": content_index,
                                "delta": chunk,
                            },
                        )
                    )
                events.append(
                    (
                        "response.output_text.done",
                        {
                            "type": "response.output_text.done",
                            "item_id": item_id,
                            "output_index": output_index,
                            "content_index": content_index,
                            "text": text,
                        },
                    )
                )
                events.append(
                    (
                        "response.content_part.done",
                        {
                            "type": "response.content_part.done",
                            "item_id": item_id,
                            "output_index": output_index,
                            "content_index": content_index,
                            "part": {"type": "output_text", "text": text},
                        },
                    )
                )
        events.append(
            (
                "response.output_item.done",
                {"type": "response.output_item.done", "output_index": output_index, "item": item},
            )
        )
    events.append(("response.completed", {"type": "response.completed", "response": completed_response}))
    return [_sse(event, data) for event, data in events]


def chat_completion_stream_events(response: dict[str, Any], *, include_role: bool = True) -> list[bytes]:
    """Encode a non-stream chat completion as OpenAI-compatible SSE events.

    The gateway still performs policy checks on a complete assistant message, then
    emits a standards-shaped stream for agents that require `stream=true`.
    """
    model = str(response.get("model") or "AgentBrake-Fusion/local")
    message = ((response.get("choices") or [{}])[0].get("message") or {}) if isinstance(response.get("choices"), list) else {}
    finish_reason = (
        ((response.get("choices") or [{}])[0].get("finish_reason") or "stop") if isinstance(response.get("choices"), list) else "stop"
    )
    stream_id = str(response.get("id") or new_id("chatcmpl"))
    created = response.get("created") or utc_now()
    events: list[dict[str, Any]] = []
    if include_role:
        events.append(
            {
                "id": stream_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
            }
        )

    content = str(message.get("content") or "")
    for chunk in _content_chunks(content):
        events.append(
            {
                "id": stream_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": {"content": chunk}, "finish_reason": None}],
            }
        )

    tool_calls = message.get("tool_calls") or []
    for index, tool_call in enumerate(tool_calls):
        chunk_call: dict[str, Any] = {"index": index}
        if tool_call.get("id"):
            chunk_call["id"] = tool_call["id"]
        if tool_call.get("type"):
            chunk_call["type"] = tool_call["type"]
        function = tool_call.get("function") or {}
        if function:
            chunk_call["function"] = {
                key: value
                for key, value in {
                    "name": function.get("name"),
                    "arguments": function.get("arguments"),
                }.items()
                if value is not None
            }
        events.append(
            {
                "id": stream_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": {"tool_calls": [chunk_call]}, "finish_reason": None}],
            }
        )

    events.append(
        {
            "id": stream_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
        }
    )
    return [f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8") for event in events] + [b"data: [DONE]\n\n"]


def _sse(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode("utf-8")


def _content_chunks(content: str, size: int = 256) -> list[str]:
    if not content:
        return []
    return [content[i : i + size] for i in range(0, len(content), size)]


def safe_block_message(reason: str, decisions: list[dict[str, Any]], trace_id: str) -> dict[str, Any]:
    lines = ["AgentBrake-Fusion blocked or constrained high-risk tool calls before execution.", f"Audit trace ID: {trace_id}", ""]
    for d in decisions:
        action = d.get("action", {})
        dec = d.get("decision", {})
        lines.append(f"- Candidate action: {_redact_secret_text(action.get('raw_action'))}")
        lines.append(f"  Semantic action: {action.get('semantic_action') or 'unknown'}")
        lines.append(f"  Decision: {dec.get('decision') or 'unknown'}; risk score: {dec.get('risk_score')}")
        lines.append(f"  Reasons: {', '.join(str(code) for code in dec.get('reason_codes', []))}")
    lines.append("")
    lines.append("Available approval outcomes: reject, sandbox-only, no-network, or block lifecycle operations for this run.")
    return {"role": "assistant", "content": reason + "\n" + "\n".join(lines), "tool_calls": []}
    lines = ["AgentBrake-Fusion 已在工具执行前阻断或约束高风险工具调用。", f"审计追踪 ID：{trace_id}", ""]
    for d in decisions:
        action = d.get("action", {})
        dec = d.get("decision", {})
        lines.append(f"- 候选动作：{_redact_secret_text(action.get('raw_action'))}")
        lines.append(f"  动作语义：{_zh_semantic(action.get('semantic_action'))}")
        lines.append(f"  裁决结果：{_zh_decision(dec.get('decision'))}；风险值：{dec.get('risk_score')}")
        lines.append(f"  阻断原因：{', '.join(_zh_reason(code) for code in dec.get('reason_codes', []))}")
    lines.append("")
    lines.append("可选审批结果：拒绝、仅本次沙箱执行、仅本次无网络执行、仅本次禁止生命周期操作。")
    return {"role": "assistant", "content": reason + "\n" + "\n".join(lines), "tool_calls": []}


def safe_sandbox_only_message(reason: str, decisions: list[dict[str, Any]], trace_id: str) -> dict[str, Any]:
    lines = ["AgentBrake-Fusion constrained these tool calls to sandbox-only execution.", f"Audit trace ID: {trace_id}", ""]
    for d in decisions:
        action = d.get("action", {})
        dec = d.get("decision", {})
        lines.append(f"- Candidate action: {_redact_secret_text(action.get('raw_action'))}")
        lines.append(f"  Semantic action: {action.get('semantic_action') or 'unknown'}")
        lines.append(f"  Decision: {dec.get('decision') or 'unknown'}; risk score: {dec.get('risk_score')}")
        lines.append("  Host execution: blocked")
        lines.append("  Next step: run only through the AgentBrake-Fusion sandbox, overlay, or preflight tooling.")
    return {"role": "assistant", "content": reason + "\n" + "\n".join(lines), "tool_calls": []}
    lines = ["AgentBrake-Fusion 已将工具调用约束为仅沙箱处理。", f"审计追踪 ID：{trace_id}", ""]
    for d in decisions:
        action = d.get("action", {})
        dec = d.get("decision", {})
        lines.append(f"- 候选动作：{_redact_secret_text(action.get('raw_action'))}")
        lines.append(f"  动作语义：{_zh_semantic(action.get('semantic_action'))}")
        lines.append(f"  裁决结果：{_zh_decision(dec.get('decision'))}；风险值：{dec.get('risk_score')}")
        lines.append("  主机执行：已禁止")
        lines.append("  下一步：只能通过 AgentBrake-Fusion 沙箱、覆盖层或预检工具运行")
    return {"role": "assistant", "content": reason + "\n" + "\n".join(lines), "tool_calls": []}


def _zh_decision(value: Any) -> str:
    return {
        "allow": "放行",
        "block": "阻断",
        "quarantine": "隔离",
        "require_confirmation": "需要人工确认",
        "sandbox_then_approval": "沙箱执行后审批",
        "allow_in_sandbox": "仅允许沙箱执行",
    }.get(str(value or ""), str(value or "未知"))


def _zh_semantic(value: Any) -> str:
    return {
        "unknown_side_effect": "未知副作用动作",
        "external_send": "外部发送动作",
        "secret_read": "读取敏感信息",
        "file_write": "文件写入",
        "file_delete": "文件删除",
        "network_request": "网络请求",
        "command_execution": "命令执行",
    }.get(str(value or ""), str(value or "未知"))


def _zh_reason(value: Any) -> str:
    code = str(value or "")
    return {
        "unknown_action_semantics": "动作语义未知，按高风险处理",
        "repo_escape_or_symlink_escape": "路径越界或符号链接逃逸风险",
        "default_fail_closed": "默认闭环策略：无法确认安全时阻断",
        "path_escape_repo_root": "路径逃逸出仓库根目录",
        "symlink_escape_repo_root": "符号链接逃逸出仓库根目录",
        "secret_exfiltration": "存在敏感信息外传风险",
        "external_egress": "存在外部网络发送风险",
        "requires_human_approval": "需要人工审批",
    }.get(code, code)


def _redact_secret_text(value: Any) -> str:
    text = str(value or "")
    token_re = re.compile(r"(ghp_[A-Za-z0-9_\-]{10,}|npm_[A-Za-z0-9_\-]{8,}|RS_CANARY_[A-Z0-9_]+)")
    kv_re = re.compile(r"(?i)(password|token|secret|api_key)=([^\s&]+)")
    bearer_re = re.compile(r"(?i)(Authorization\s*:\s*Bearer\s+)[^\s'\"]+")
    text = token_re.sub("<REDACTED_TOKEN>", text)
    text = kv_re.sub(r"\1=<REDACTED>", text)
    text = bearer_re.sub(r"\1<REDACTED>", text)
    return text
