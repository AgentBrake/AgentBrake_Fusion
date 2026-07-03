"""Tiny local approval HTTP API for AgentBrake-Fusion demos."""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .approvals import ApprovalCenter, ApprovalStore
from .models import ApprovalRequest

MAX_APPROVAL_BODY_BYTES = 1024 * 1024


def approval_events_summary(store: ApprovalStore) -> dict[str, Any]:
    events = store.list_events()
    requests = [e for e in events if e.get("event_type") == "request"]
    grants = [e for e in events if e.get("event_type") == "grant"]
    denials = [e for e in events if e.get("event_type") == "denial"]
    return {
        "metrics": {
            "requests": len(requests),
            "grants": len(grants),
            "denials": len(denials),
            "pending": max(len(requests) - len(grants) - len(denials), 0),
        },
        "events": events,
    }


def serve_approval_api(
    store_path: str | Path,
    host: str = "127.0.0.1",
    port: int = 8776,
    api_key: str | None = None,
) -> None:
    store = ApprovalStore(store_path)
    required_key = api_key if api_key is not None else os.getenv("AGENTBRAKE_APPROVAL_API_KEY", "agentbrake-fusion-local")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path not in {"/approvals", "/v1/approvals"}:
                self._json({"error": "not found"}, status=404)
                return
            if not self._authorized(required_key):
                return
            self._json(approval_events_summary(store))

        def do_POST(self) -> None:  # noqa: N802
            try:
                if not self._authorized(required_key):
                    return
                parts = [p for p in self.path.strip("/").split("/") if p]
                if len(parts) not in {3, 4}:
                    self._json({"error": "expected /approvals/{id}/approve or /approvals/{id}/deny"}, status=404)
                    return
                if parts[0] == "v1":
                    parts = parts[1:]
                if len(parts) != 3 or parts[0] != "approvals" or parts[2] not in {"approve", "deny"}:
                    self._json({"error": "expected /approvals/{id}/approve or /approvals/{id}/deny"}, status=404)
                    return
                approval_id, action = parts[1], parts[2]
                request = _find_request(store, approval_id)
                if not request:
                    self._json({"error": f"approval request not found: {approval_id}"}, status=404)
                    return
                payload = self._read_json()
                if action == "approve":
                    grant = ApprovalCenter().grant(
                        request,
                        constraints=list(payload.get("constraints") or ["sandbox_only", "no_network"]),
                        minutes=int(payload.get("minutes") or 30),
                        granted_by=str(payload.get("granted_by") or "approval_api"),
                    )
                    store.append_grant(grant)
                    self._json({"grant": asdict(grant)})
                    return
                store.append_denial(request, denied_by=str(payload.get("denied_by") or "approval_api"))
                self._json({"approval_request_id": approval_id, "decision": "denied"})
            except ValueError as exc:
                status = 413 if "too large" in str(exc) else 400
                self._json({"error": str(exc)}, status=status)

        def _authorized(self, key: str | None) -> bool:
            if key and self.headers.get("Authorization") != f"Bearer {key}":
                self._json({"error": "missing or invalid Authorization bearer token"}, status=401)
                return False
            return True

        def _read_json(self) -> dict[str, Any]:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            if content_length > MAX_APPROVAL_BODY_BYTES:
                raise ValueError("request body too large")
            body = self.rfile.read(content_length)
            return json.loads(body.decode("utf-8") or "{}")

        def _json(self, payload: dict[str, Any], status: int = 200) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, _format: str, *args: object) -> None:
            return

    ThreadingHTTPServer((host, port), Handler).serve_forever()


def _find_request(store: ApprovalStore, approval_request_id: str) -> ApprovalRequest | None:
    for event in reversed(store.list_events()):
        if event.get("event_type") == "request" and event.get("payload", {}).get("approval_request_id") == approval_request_id:
            return ApprovalRequest(**event["payload"])
    return None
