"""Stable multi-turn session identity resolution for Gateway requests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import new_id, sha256_json


@dataclass(slots=True)
class SessionIdentity:
    run_id: str
    conversation_id: str | None = None
    turn_id: str | None = None
    client_id: str | None = None
    task_id: str | None = None
    source: str = "unknown"


def resolve_session_identity(
    *,
    request: dict[str, Any],
    repo_root: str | Path,
    headers: dict[str, Any] | None = None,
) -> SessionIdentity:
    metadata = request.get("metadata") if isinstance(request.get("metadata"), dict) else {}
    headers = headers or {}
    conversation_id = _first(metadata, request, "conversation_id", "thread_id", "session_id")
    turn_id = _first(metadata, request, "turn_id", "request_id", "trace_id")
    client_id = _first(metadata, request, "client_id", "user", "user_id")
    task_id = _first(metadata, request, "task_id")

    explicit = metadata.get("agentbrake_run_id")
    if explicit:
        return SessionIdentity(str(explicit), conversation_id, turn_id, client_id, task_id, "metadata.agentbrake_run_id")
    explicit = metadata.get("run_id")
    if explicit:
        return SessionIdentity(str(explicit), conversation_id, turn_id, client_id, task_id, "metadata.run_id")
    header_run = _header(headers, "X-AgentBrake-Fusion-Run-Id")
    if header_run:
        return SessionIdentity(header_run, conversation_id, turn_id, client_id, task_id, "header.x-AgentBrake-Fusion-run-id")

    if conversation_id:
        return SessionIdentity(
            _derive_run_id(repo_root, conversation_id, client_id), conversation_id, turn_id, client_id, task_id, "derived.conversation"
        )
    request_conv = request.get("conversation_id") or request.get("thread_id") or request.get("session_id")
    if request_conv:
        text = str(request_conv)
        return SessionIdentity(
            _derive_run_id(repo_root, text, client_id), text, turn_id, client_id, task_id, "derived.request_conversation"
        )
    if client_id:
        message_hash = _first_user_message_hash(request)
        return SessionIdentity(
            _derive_run_id(repo_root, message_hash, client_id),
            conversation_id,
            turn_id,
            client_id,
            task_id,
            "derived.client_message" if message_hash else "derived.client",
        )
    return SessionIdentity(
        str(request.get("trace_id") or request.get("request_id") or new_id("gw_trace")),
        conversation_id,
        turn_id,
        client_id,
        task_id,
        "generated",
    )


def _first(metadata: dict[str, Any], request: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if value:
            return str(value)
    for key in keys:
        value = request.get(key)
        if value:
            return str(value)
    return None


def _header(headers: dict[str, Any], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted and value:
            return str(value)
    return None


def _derive_run_id(repo_root: str | Path, conversation_id: str, client_id: str | None) -> str:
    seed = {
        "repo_root": str(Path(repo_root).resolve()),
        "conversation_id": conversation_id,
        "client_id": client_id or "",
    }
    return "run_" + sha256_json(seed).removeprefix("sha256:")[:16]


def _first_user_message_hash(request: dict[str, Any]) -> str:
    messages = request.get("messages")
    if not isinstance(messages, list):
        return ""
    for message in messages:
        if isinstance(message, dict) and message.get("role") == "user":
            return sha256_json({"content": message.get("content")}).removeprefix("sha256:")[:16]
    return ""
