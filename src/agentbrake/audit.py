"""Hash-chain audit log and replay bundle support."""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
from dataclasses import asdict
from enum import StrEnum
from pathlib import Path
from typing import Any

from .models import AuditEvent, new_id, sha256_json, stable_json, utc_now


class AuditEventType(StrEnum):
    ASSET_SCAN = "asset_scan"
    SOURCE_INGESTED = "source_ingested"
    TASK_CONTRACT = "task_contract"
    ACTION_PARSED = "action_parsed"
    SECRET_EVENT = "secret_event"
    PACKAGE_EVENT = "package_event"
    MCP_INVOCATION = "mcp_invocation"
    MEMORY_EVENT = "memory_event"
    EXEC_TRACE = "exec_trace"
    POLICY_DECISION = "policy_decision"
    POLICY_FACT_SET = "policy_fact_set"
    POLICY_EVAL_TRACE = "policy_eval_trace"
    POLICY_RUNTIME = "policy_runtime"
    POLICY_OVERRIDE_EVENT = "policy_override_event"
    HOST_EXEC_STARTED = "host_exec_started"
    HOST_EXEC_COMPLETED = "host_exec_completed"
    GATEWAY_RESPONSE = "gateway_response"
    ACTION_GRAPH = "action_graph"
    SESSION_STATE_UPDATE = "session_state_update"
    SESSION_STATE_PERSISTED = "session_state_persisted"
    SESSION_STATE_RESTORE = "session_state_restore"
    CONSTRAINT_LATTICE_TRACE = "constraint_lattice_trace"


class AuditLog:
    def __init__(self, log_path: str | Path, session_id: str | None = None, *, buffered: bool | None = None):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id or new_id("sess")
        self._lock = threading.RLock()
        self.buffered = (os.getenv("AGENTBRAKE_AUDIT_BUFFERED", "").lower() in {"1", "true", "yes", "on"}) if buffered is None else buffered
        self._buffer: list[str] = []
        self._buffer_limit = max(1, int(os.getenv("AGENTBRAKE_AUDIT_BUFFER_LIMIT", "20")))
        self._head = self._read_head()
        self.append_latency_samples_ms: list[float] = []

    @property
    def head(self) -> str:
        return self._head

    def append(
        self,
        event_type: str,
        payload: dict[str, Any],
        task_id: str | None = None,
        actor: str = "agentbrake",
        source_ids: list[str] | None = None,
        action_id: str | None = None,
        decision_id: str | None = None,
    ) -> AuditEvent:
        with self._lock:
            start = time.perf_counter()
            redacted_payload = self._redact_payload(payload)
            event_without_hash = {
                "event_id": new_id("evt"),
                "schema_version": "audit-event-v2",
                "prev_hash": self._head,
                "timestamp": utc_now(),
                "session_id": self.session_id,
                "task_id": task_id,
                "actor": actor,
                "event_type": event_type,
                "payload": redacted_payload,
                "source_ids": source_ids or [],
                "action_id": action_id,
                "decision_id": decision_id,
                "redaction": {"secret_values": "redacted", "stored_secret_hashes": True},
            }
            self._validate_event(event_without_hash)
            event_hash = sha256_json(event_without_hash)
            event = AuditEvent(event_hash=event_hash, **event_without_hash)
            line = stable_json(asdict(event)) + "\n"
            if self.buffered:
                self._buffer.append(line)
                if len(self._buffer) >= self._buffer_limit:
                    self.flush()
            else:
                with self.log_path.open("a", encoding="utf-8") as f:
                    f.write(line)
            self._head = event_hash
            self.append_latency_samples_ms.append((time.perf_counter() - start) * 1000)
            return event

    def flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            with self.log_path.open("a", encoding="utf-8") as f:
                f.writelines(self._buffer)
            self._buffer = []

    def latency_stats(self) -> dict[str, float]:
        return {
            "audit_append_avg_ms": _avg(self.append_latency_samples_ms),
            "audit_append_p50_ms": _p50(self.append_latency_samples_ms),
            "audit_append_p95_ms": _p95(self.append_latency_samples_ms),
        }

    def verify(self) -> tuple[bool, list[str]]:
        self.flush()
        errors: list[str] = []
        prev = "GENESIS"
        for i, event in enumerate(self.read_events(), start=1):
            if event.get("prev_hash") != prev:
                errors.append(f"line {i}: prev_hash mismatch")
            stored = event.get("event_hash")
            copy = dict(event)
            copy.pop("event_hash", None)
            recomputed = sha256_json(copy)
            if stored != recomputed:
                errors.append(f"line {i}: event_hash mismatch")
            prev = stored or ""
        return not errors, errors

    def read_events(self) -> list[dict[str, Any]]:
        self.flush()
        if not self.log_path.exists():
            return []
        with self._lock:
            events = []
            with self.log_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
            return events

    def incident_graph(self) -> dict[str, Any]:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, str]] = []
        seen: set[str] = set()
        for event in self.read_events():
            event_id = event["event_id"]
            node_type = event.get("event_type", "event")
            if event_id not in seen:
                nodes.append({"id": event_id, "type": node_type, "label": self._label_for(event), "hash": event.get("event_hash")})
                seen.add(event_id)
            for sid in event.get("source_ids", []) or []:
                if sid not in seen:
                    nodes.append({"id": sid, "type": "source", "label": sid})
                    seen.add(sid)
                edges.append({"from": sid, "to": event_id, "relation": "influenced"})
            aid = event.get("action_id")
            if aid and aid not in seen:
                nodes.append({"id": aid, "type": "action", "label": aid})
                seen.add(aid)
            if aid:
                edges.append({"from": aid, "to": event_id, "relation": "recorded_as"})
            decision_id = event.get("decision_id")
            if decision_id:
                edges.append({"from": event_id, "to": decision_id, "relation": "decision"})
        return {"nodes": nodes, "edges": edges, "hash_head": self._head, "event_count": len(nodes)}

    def write_replay_bundle(
        self, bundle_dir: str | Path, repo_snapshot: str | Path | None = None, extra: dict[str, Any] | None = None
    ) -> Path:
        bundle = Path(bundle_dir)
        bundle.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.log_path, bundle / "audit.jsonl")
        (bundle / "incident_graph.json").write_text(json.dumps(self.incident_graph(), ensure_ascii=False, indent=2), encoding="utf-8")
        spec = {
            "replay_bundle_id": new_id("replay"),
            "created_at": utc_now(),
            "audit_log": "audit.jsonl",
            "incident_graph": "incident_graph.json",
            "policy_version": (extra or {}).get("policy_version", "agentbrake-mvp-policy-v0.1"),
            "sandbox_image": "mvp-dry-run-sandbox",
            "model_agent_config": (extra or {}).get("model_agent_config", "reference-agent-v0.1"),
            "random_seed": (extra or {}).get("random_seed", 1337),
            "clock_seed": (extra or {}).get("clock_seed", "fixed-by-audit-timestamps"),
            "redaction": {"secret_values": "redacted", "stored_secret_hashes": True},
        }
        if repo_snapshot:
            dst = bundle / "repo_snapshot"
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(repo_snapshot, dst, ignore=shutil.ignore_patterns("node_modules", ".git", ".venv"))
            spec["repo_snapshot"] = "repo_snapshot"
        (bundle / "replay_spec.json").write_text(json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8")
        return bundle

    def _read_head(self) -> str:
        if not self.log_path.exists():
            return "GENESIS"
        head = "GENESIS"
        for event in self.read_events():
            head = event.get("event_hash", head)
        return head

    @staticmethod
    def _redact_payload(payload: Any) -> Any:
        """Recursively redact values without corrupting JSON structure."""
        import re

        token_re = re.compile(r"(ghp_[A-Za-z0-9_\-]{10,}|npm_[A-Za-z0-9_\-]{8,}|RS_CANARY_[A-Z0-9_]+)")
        kv_re = re.compile(r"(?i)(password|token|secret|api_key)=([^\s&]+)")

        def walk(value: Any, key: str = "") -> Any:
            key_low = key.lower()
            if isinstance(value, dict):
                return {k: walk(v, str(k)) for k, v in value.items()}
            if isinstance(value, list):
                return [walk(v, key) for v in value]
            if isinstance(value, str):
                if key_low in {"value", "secret", "token", "password", "api_key"}:
                    return "<REDACTED>"
                value = token_re.sub("<REDACTED_TOKEN>", value)
                value = kv_re.sub(r"\1=<REDACTED>", value)
                return value
            return value

        return walk(payload)

    @staticmethod
    def _validate_event(event: dict[str, Any]) -> None:
        required = {"event_id", "schema_version", "prev_hash", "timestamp", "session_id", "actor", "event_type", "payload"}
        missing = sorted(required - set(event))
        if missing:
            raise ValueError(f"audit event missing required fields: {', '.join(missing)}")
        if not isinstance(event.get("payload"), dict):
            raise TypeError("audit event payload must be a dict")

    @staticmethod
    def _label_for(event: dict[str, Any]) -> str:
        payload = event.get("payload", {})
        if event.get("event_type") == "policy_decision":
            return f"{payload.get('decision')}:{payload.get('reason_codes', [''])[0] if payload.get('reason_codes') else ''}"
        if event.get("event_type") == "action_parsed":
            return payload.get("semantic_action", "action")
        if event.get("event_type") == "source_ingested":
            return payload.get("source_type", "source")
        return event.get("event_type", "event")


def _avg(values: list[float]) -> float:
    return float(sum(values) / len(values)) if values else 0.0


def _p50(values: list[float]) -> float:
    return _percentile(values, 0.5)


def _p95(values: list[float]) -> float:
    return _percentile(values, 0.95)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((len(ordered) - 1) * pct)))
    return float(ordered[idx])
