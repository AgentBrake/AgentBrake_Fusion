"""AgentBrake-Fusion OpenAI-compatible Governance Gateway."""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..approvals import ApprovalCenter, ApprovalStore
from ..audit import AuditLog
from ..control_plane import AgentBrakeControlPlane
from ..eval.fast_mode import load_eval_fast_mode_config
from ..instruction_ir import InstructionBuilder, InstructionLowerer
from ..instruction_ir import to_dict as instruction_to_dict
from ..models import new_id, sha256_json
from ..plugins import ToolParserRegistry
from ..policy_runtime import PolicyRuntime
from .openai_compat import (
    chat_completion_stream_events,
    extract_messages,
    latest_user_text,
    responses_api_response,
    responses_api_stream_events,
)
from .response_transform import transform_response
from .session_identity import resolve_session_identity
from .trace_state import GatewayTrace
from .upstream import LocalHeuristicUpstream, OpenAICompatibleUpstream

MAX_GATEWAY_BODY_BYTES = 2 * 1024 * 1024


class AgentBrakeGateway:
    def __init__(
        self,
        repo_root: str | Path,
        audit_path: str | Path | None = None,
        policy_mode: str = "enforce",
        policy_role: str = "local_dev_strict",
        upstream: Any | None = None,
        agent_type: str = "openai",
        policy_config: str | Path | None = None,
        release_mode: str = "gateway_only",
        approval_store_path: str | Path | None = None,
        unsafe_allow_disabled_policy: bool = False,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.fast_mode = load_eval_fast_mode_config()
        self.audit = AuditLog(audit_path or self.repo_root / ".agentbrake" / "gateway_audit.jsonl", buffered=self.fast_mode.audit_buffered)
        self.policy_config = policy_config
        self.session_state_path = self.repo_root / ".agentbrake" / "session_state.jsonl"
        self.session_state_store = None
        if self.fast_mode.session_cache:
            from ..session_state import PersistentSessionStateStore

            self.session_state_store = PersistentSessionStateStore(self.session_state_path, audit_log=self.audit)
        self.cp = self._new_request_control_plane()
        self.policy_runtime = PolicyRuntime(mode=policy_mode, role=policy_role, unsafe_allow_disabled=unsafe_allow_disabled_policy)  # type: ignore[arg-type]
        self.upstream = upstream or LocalHeuristicUpstream()
        self.agent_type = agent_type
        self.registry = ToolParserRegistry()
        self.release_mode = release_mode
        self.approvals = ApprovalCenter()
        self.approval_store = ApprovalStore(approval_store_path or self.repo_root / ".agentbrake" / "gateway_approvals.jsonl")

    def _new_request_control_plane(self, run_id: str | None = None) -> AgentBrakeControlPlane:
        return AgentBrakeControlPlane(
            self.repo_root,
            audit=self.audit,
            policy_config=self.policy_config,
            session_state_path=self.session_state_path,
            session_state_store=self.session_state_store,
            run_id=run_id,
            fast_mode=self.fast_mode,
        )

    def handle_chat_completion(self, request: dict[str, Any]) -> dict[str, Any]:
        identity = resolve_session_identity(
            request=request,
            repo_root=self.repo_root,
            headers=request.get("_headers") if isinstance(request.get("_headers"), dict) else None,
        )
        run_id = identity.run_id
        request["trace_id"] = run_id
        request.setdefault("metadata", {})["agentbrake_run_id"] = run_id
        cp = self._new_request_control_plane(run_id)
        self.cp = cp
        cp.audit.append(
            "session_identity_resolved",
            {
                "run_id": identity.run_id,
                "conversation_id": identity.conversation_id,
                "turn_id": identity.turn_id,
                "client_id": identity.client_id,
                "task_id": identity.task_id,
                "source": identity.source,
            },
            actor="gateway",
        )
        lowerer = InstructionLowerer(cp.parser)
        trace = GatewayTrace(trace_id=run_id)
        messages = extract_messages(request)
        turn_id = trace.new_turn("chat_completion", {"model": request.get("model"), "message_count": len(messages)})
        cp.audit.append(
            "gateway_pre_call",
            {
                "trace_id": trace.trace_id,
                "turn_id": turn_id,
                "model": request.get("model"),
                "message_count": len(messages),
                "request_hash": sha256_json(request),
            },
            actor="gateway",
        )

        cp.build_contract(str(request.get("task") or latest_user_text(messages) or "general code maintenance task"))
        contexts = self._ingest_contexts(request, cp)
        source_ids = [c["source_id"] for c in contexts]
        tool_mappings = self._introspect_request_tools(request)
        if tool_mappings:
            cp.audit.append(
                "tool_mappings_introspected",
                {
                    "trace_id": trace.trace_id,
                    "turn_id": turn_id,
                    "mapping_count": len(tool_mappings),
                    "tools": [m.tool_name for m in tool_mappings],
                },
                task_id=cp.contract.task_id if cp.contract else None,
                actor="tool_introspector",
            )

        upstream_contexts = [{"source_id": sid, "content": c.get("content", "")} for sid, c in zip(source_ids, contexts)]
        request_preview = {
            "keys": sorted(str(k) for k in request.keys() if k not in {"messages", "input", "tools", "metadata", "contexts"}),
            "message_count": len(messages),
            "tool_count": len(request.get("tools") or []) if isinstance(request.get("tools"), list) else 0,
            "has_headers": "_headers" in request,
            "stream": bool(request.get("stream")),
        }
        cp.audit.append(
            "gateway_request_preview",
            request_preview,
            task_id=cp.contract.task_id if cp.contract else None,
            actor="gateway",
        )
        cp.audit.flush()
        try:
            if request.get("stream") and hasattr(self.upstream, "complete_streaming"):
                assistant_msg = self.upstream.complete_streaming(request, contexts=upstream_contexts)
            else:
                assistant_msg = self.upstream.complete(request, contexts=upstream_contexts)
        except Exception as exc:
            cp.audit.append(
                "gateway_upstream_error",
                {
                    "trace_id": trace.trace_id,
                    "turn_id": turn_id,
                    "error_type": type(exc).__name__,
                    "detail": str(exc)[:2000],
                    "request_preview": request_preview,
                },
                task_id=cp.contract.task_id if cp.contract else None,
                actor="gateway",
            )
            cp.audit.flush()
            raise
        cp.audit.append(
            "gateway_post_call",
            {
                "trace_id": trace.trace_id,
                "turn_id": turn_id,
                "assistant_hash": sha256_json(assistant_msg),
                "tool_call_count": len(assistant_msg.get("tool_calls", []) or []),
            },
            task_id=cp.contract.task_id if cp.contract else None,
            actor="gateway",
        )

        trust_floor = "untrusted" if source_ids else "trusted"
        builder = InstructionBuilder(trace_id=trace.trace_id, registry=self.registry)
        instructions = builder.response_to_instructions(
            assistant_msg, turn_id=turn_id, source_ids=source_ids, agent_type=self.agent_type, trust_floor=trust_floor
        )  # type: ignore[arg-type]

        guarded: list[dict[str, Any]] = []
        for ins in instructions:
            cp.audit.append(
                "instruction_ir",
                instruction_to_dict(ins),
                task_id=cp.contract.task_id if cp.contract else None,
                actor="instruction_builder",
                source_ids=ins.source_ids,
            )
            action = lowerer.lower(ins, cwd=self.repo_root)
            if not action:
                continue
            action2, decision = cp.guard_action_ir(action)
            runtime = self.policy_runtime.apply(decision)
            item = {
                "instruction": instruction_to_dict(ins),
                "action": asdict(action2),
                "decision": asdict(decision),
                "runtime": runtime.to_dict(),
            }
            if runtime.effective_decision in {"block", "quarantine", "require_confirmation", "sandbox_then_approval"}:
                assert cp.contract is not None
                plan = {"trace_id": trace.trace_id, "instructions": [instruction_to_dict(i) for i in instructions]}
                approval = self.approvals.create_request(cp.contract, action2, decision, cp.provenance.graph, plan=plan)
                self.approval_store.append_request(approval)
                approval_payload = asdict(approval)
                item["approval_request"] = approval_payload
                item["confirmation_request"] = approval_payload
                cp.audit.append(
                    "gateway_approval_request",
                    approval_payload,
                    task_id=cp.contract.task_id if cp.contract else None,
                    actor="gateway",
                    source_ids=action2.source_ids,
                    action_id=action2.action_id,
                )
            cp.audit.append(
                "policy_runtime",
                runtime.to_dict(),
                task_id=cp.contract.task_id if cp.contract else None,
                actor="policy_runtime",
                source_ids=action2.source_ids,
                action_id=action2.action_id,
                decision_id=decision.decision_id,
            )
            guarded.append(item)

        response = transform_response(
            assistant_msg, guarded, trace.trace_id, model=str(request.get("model") or "AgentBrake-Fusion/local"), release_mode=self.release_mode
        )
        result = {
            "trace_id": trace.trace_id,
            "turn_id": turn_id,
            "response": response,
            "instructions": [instruction_to_dict(i) for i in instructions],
            "guarded_results": guarded,
            "audit_log": str(cp.audit.log_path),
        }
        cp.audit.append(
            "gateway_response",
            {
                "trace_id": trace.trace_id,
                "turn_id": turn_id,
                "blocked_count": sum(
                    1
                    for g in guarded
                    if g.get("runtime", {}).get("effective_decision")
                    in {"block", "quarantine", "require_confirmation", "sandbox_then_approval"}
                ),
                "response_hash": sha256_json(response),
            },
            task_id=cp.contract.task_id if cp.contract else None,
            actor="gateway",
        )
        return result

    def _introspect_request_tools(self, request: dict[str, Any]):
        mappings = []
        if isinstance(request.get("tools"), list):
            mappings.extend(self.registry.introspect_openai_tools(request["tools"], source="gateway_request.tools"))
        metadata = request.get("metadata") or {}
        manifests = metadata.get("mcp_manifests") or request.get("mcp_manifests") or []
        for manifest in manifests if isinstance(manifests, list) else [manifests]:
            if isinstance(manifest, dict):
                mappings.extend(self.registry.introspect_mcp_manifest(manifest, source="gateway_request.mcp_manifest"))
        agent_config = metadata.get("agent_config") or request.get("agent_config")
        if isinstance(agent_config, dict):
            mappings.extend(self.registry.introspect_agent_config(agent_config, source="gateway_request.agent_config"))
        return mappings

    def _ingest_contexts(self, request: dict[str, Any], cp: AgentBrakeControlPlane) -> list[dict[str, Any]]:
        metadata = request.get("metadata") or {}
        raw_contexts = metadata.get("contexts") or request.get("contexts") or []
        contexts: list[dict[str, Any]] = []
        for idx, ctx in enumerate(raw_contexts):
            if isinstance(ctx, str):
                ctx = {"source_type": "external_text", "content": ctx, "source_id": f"src_gateway_ctx_{idx + 1:03d}"}
            content = str(ctx.get("content") or "")
            source_type = str(ctx.get("source_type") or ctx.get("type") or "external_text")
            source_id = str(ctx.get("source_id") or f"src_gateway_ctx_{idx + 1:03d}")
            src = cp.ingest_source(
                source_type, content, retrieval_path=str(ctx.get("retrieval_path") or "gateway_context"), source_id=source_id
            )
            contexts.append({"source_id": src.source_id, "source_type": source_type, "content": content})
        return contexts


def simulate_gateway_request(
    repo_root: str | Path, request: dict[str, Any], audit_path: str | Path | None = None, policy_mode: str = "enforce"
) -> dict[str, Any]:
    gw = AgentBrakeGateway(
        repo_root,
        audit_path=audit_path,
        policy_mode=policy_mode,
        unsafe_allow_disabled_policy=bool(request.get("unsafe_allow_disabled_policy")),
    )
    return gw.handle_chat_completion(request)


def make_upstream(
    upstream_base_url: str | None = None,
    upstream_api_key: str | None = None,
    *,
    upstream_chat_path: str = "/chat/completions",
    upstream_timeout: float = 60.0,
) -> Any:
    if upstream_base_url:
        return OpenAICompatibleUpstream(
            base_url=upstream_base_url,
            api_key=upstream_api_key,
            chat_path=upstream_chat_path,
            timeout=upstream_timeout,
        )
    return LocalHeuristicUpstream()


def serve_gateway(
    repo_root: str | Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    audit_path: str | Path | None = None,
    policy_mode: str = "enforce",
    upstream_base_url: str | None = None,
    upstream_api_key: str | None = None,
    upstream_chat_path: str = "/chat/completions",
    upstream_timeout: float = 60.0,
    policy_config: str | Path | None = None,
    gateway_api_key: str | None = None,
    release_mode: str = "gateway_only",
    unsafe_allow_disabled_policy: bool = False,
    upstream: Any | None = None,
    stream_heartbeat_interval: float = 10.0,
) -> None:
    """Start a tiny standard-library OpenAI-compatible HTTP server.

    Routes: POST /v1/chat/completions and POST /v1/responses.  This is intended
    for local demos and integration tests; production can wrap AgentBrakeGateway
    in FastAPI/LiteLLM or another server without changing the gateway core.
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    if policy_mode == "disabled" and host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("Refusing to run disabled policy mode on a non-loopback gateway host.")
    gateway = AgentBrakeGateway(
        repo_root,
        audit_path=audit_path,
        policy_mode=policy_mode,
        policy_config=policy_config,
        release_mode=release_mode,
        unsafe_allow_disabled_policy=unsafe_allow_disabled_policy,
        upstream=upstream
        or make_upstream(
            upstream_base_url=upstream_base_url,
            upstream_api_key=upstream_api_key,
            upstream_chat_path=upstream_chat_path,
            upstream_timeout=upstream_timeout,
        ),
    )
    env_gateway_key = os.getenv("AGENTBRAKE_GATEWAY_API_KEY")
    if host not in {"127.0.0.1", "localhost", "::1"} and gateway_api_key is None and not env_gateway_key:
        raise RuntimeError("Refusing to expose gateway on a non-loopback host without an explicit bearer token.")
    required_gateway_key = gateway_api_key if gateway_api_key is not None else env_gateway_key or "agentbrake-fusion-local"
    if host not in {"127.0.0.1", "localhost", "::1"}:
        gateway.cp.audit.append("gateway_network_exposure_warning", {"host": host, "requires_authorization": True}, actor="gateway")
        print("AgentBrake-Fusion warning: gateway is listening on a non-loopback host; Authorization is required.", flush=True)

    class Handler(BaseHTTPRequestHandler):
        def _write_sse_data(self, payload: dict[str, Any]) -> None:
            self.wfile.write(f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8"))
            self.wfile.flush()

        def _write_sse_comment(self, comment: str) -> None:
            self.wfile.write(f": {comment}\n\n".encode("utf-8"))
            self.wfile.flush()

        def _serve_streaming_chat_completion(self, request: dict[str, Any]) -> None:
            identity = resolve_session_identity(
                request=request,
                repo_root=gateway.repo_root,
                headers=request.get("_headers") if isinstance(request.get("_headers"), dict) else None,
            )
            trace_id = identity.run_id
            request["trace_id"] = trace_id
            request.setdefault("metadata", {})["agentbrake_run_id"] = trace_id
            stream_id = new_id("chatcmpl")
            created = int(time.time())
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("X-AgentBrake-Fusion-Trace-Id", trace_id)
            self.send_header("X-AgentBrake-Fusion-Run-Id", trace_id)
            self.end_headers()
            if self.path == "/v1/chat/completions":
                self._write_sse_data(
                    {
                        "id": stream_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": str(request.get("model") or "AgentBrake-Fusion/local"),
                        "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
                    }
                )

            results: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=1)

            def run_gateway() -> None:
                try:
                    results.put(("ok", gateway.handle_chat_completion(request)))
                except Exception as exc:  # pragma: no cover - exercised through HTTP handler
                    results.put(("error", exc))

            worker = threading.Thread(target=run_gateway, daemon=True)
            worker.start()
            interval = max(float(stream_heartbeat_interval), 0.1)
            while True:
                try:
                    status, value = results.get(timeout=interval)
                    break
                except queue.Empty:
                    self._write_sse_comment("AgentBrake-Fusion heartbeat")

            if status == "error":
                exc = value
                gateway.cp.audit.append(
                    "gateway_error",
                    {"path": self.path, "error_type": type(exc).__name__, "detail": str(exc)},
                    actor="gateway",
                )
                self._write_sse_data(
                    {
                        "id": stream_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": str(request.get("model") or "AgentBrake-Fusion/local"),
                        "choices": [{"index": 0, "delta": {"content": "AgentBrake-Fusion upstream request failed."}, "finish_reason": None}],
                    }
                )
                self._write_sse_data(
                    {
                        "id": stream_id,
                        "object": "chat.completion.chunk",
                        "created": created,
                        "model": str(request.get("model") or "AgentBrake-Fusion/local"),
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                    }
                )
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
                self.close_connection = True
                return

            result = value
            payload = result["response"]
            if self.path == "/v1/responses":
                payload = responses_api_response(payload, str(result["trace_id"]))
                for event in responses_api_stream_events(payload):
                    self.wfile.write(event)
                    self.wfile.flush()
                self.close_connection = True
                return
            payload["AgentBrake-Fusion"] = {
                "trace_id": result["trace_id"],
                "audit_log": result["audit_log"],
                "guarded_results": result["guarded_results"],
            }
            for event in chat_completion_stream_events(payload, include_role=False):
                self.wfile.write(event)
                self.wfile.flush()
            self.close_connection = True

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            if self.path not in {"/v1/chat/completions", "/v1/responses"}:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            if required_gateway_key and self.headers.get("Authorization") != f"Bearer {required_gateway_key}":
                gateway.cp.audit.append(
                    "rejected_gateway_request", {"path": self.path, "reason": "missing_or_invalid_authorization"}, actor="gateway"
                )
                self.send_response(401)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(b'{"error":"missing or invalid Authorization bearer token"}')
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0") or "0")
                if content_length > MAX_GATEWAY_BODY_BYTES:
                    self.send_response(413)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b'{"error":"request body too large"}')
                    return
                body = self.rfile.read(content_length)
                request = json.loads(body.decode("utf-8") or "{}")
                request["_headers"] = {key: value for key, value in self.headers.items()}
                if request.get("stream"):
                    self._serve_streaming_chat_completion(request)
                    return
                result = gateway.handle_chat_completion(request)
                payload = result["response"]
                if self.path == "/v1/responses":
                    payload = responses_api_response(payload, str(result["trace_id"]))
                payload["AgentBrake-Fusion"] = {
                    "trace_id": result["trace_id"],
                    "audit_log": result["audit_log"],
                    "guarded_results": result["guarded_results"],
                }
                data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("X-AgentBrake-Fusion-Trace-Id", str(result["trace_id"]))
                self.send_header("X-AgentBrake-Fusion-Run-Id", str(result["trace_id"]))
                self.end_headers()
                self.wfile.write(data)
            except Exception as exc:  # pragma: no cover - demo server only
                gateway.cp.audit.append(
                    "gateway_error",
                    {"path": self.path, "error_type": type(exc).__name__, "detail": str(exc)},
                    actor="gateway",
                )
                gateway.cp.audit.flush()
                print(f"AgentBrake-Fusion gateway error: {type(exc).__name__}: {exc}", flush=True)
                data = json.dumps(
                    {
                        "error": {
                            "type": "upstream_error",
                            "message": "upstream request failed",
                            "detail": str(exc)[:1000],
                        }
                    },
                    ensure_ascii=False,
                ).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        def log_message(self, _format: str, *args: object) -> None:  # quiet local demo server
            return

    ThreadingHTTPServer((host, port), Handler).serve_forever()
