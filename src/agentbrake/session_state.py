"""Session-level history summaries for cross-action policy evidence."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .audit import AuditLog
from .models import ActionIR, ExecTrace, PolicyDecision, SecretTaintEvent, SessionState, new_id, sha256_json, utc_now


class SessionStateStore:
    def __init__(self) -> None:
        self._states: dict[str, SessionState] = {}

    def load(self, run_id: str, task_id: str | None = None) -> SessionState:
        state = self._states.get(run_id)
        if state is None:
            state = SessionState(new_id("state"), run_id, task_id)
            self._states[run_id] = _finalise(state)
        elif task_id and not state.task_id:
            state.task_id = task_id
            _finalise(state)
        return state

    def update(
        self,
        action: ActionIR,
        decision: PolicyDecision,
        trace: ExecTrace | None = None,
        secret_event: SecretTaintEvent | None = None,
        *,
        run_id: str,
        task_id: str | None = None,
    ) -> SessionState:
        state = self.load(run_id, task_id)
        level = _secret_taint_level(action, decision, trace, secret_event)
        secret_assets = [str(asset) for asset in [*(action.affected_assets or []), secret_event.asset if secret_event else ""] if asset]
        if level == "attempted":
            state.attempted_secret_taint = True
            state.attempted_secret_assets.extend(secret_assets)
        elif level == "confirmed":
            state.confirmed_secret_taint = True
            state.confirmed_secret_assets.extend(secret_assets)
        if action.metadata.get("source_has_untrusted"):
            state.untrusted_source_seen = True
        if action.semantic_action in {"install_git_dependency", "install_tarball_dependency", "install_registry_dependency"}:
            state.package_taint = True
        if action.semantic_action == "modify_ci_pipeline":
            state.ci_taint = True
        if action.semantic_action == "send_network_request":
            state.prior_external_sinks.extend(str(item) for item in action.affected_assets if item)
        if trace:
            state.prior_external_sinks.extend(str(item.get("host") or item.get("url") or item) for item in trace.network_attempts)
        state.last_decisions.append(decision.decision)
        _sync_secret_compat(state)
        state.touched_secret_assets = list(dict.fromkeys(state.touched_secret_assets))[-20:]
        state.prior_external_sinks = list(dict.fromkeys(state.prior_external_sinks))[-20:]
        state.last_decisions = state.last_decisions[-20:]
        return _finalise(state)


class PersistentSessionStateStore(SessionStateStore):
    """JSONL-backed session history store.

    The persisted payload stores only policy-relevant summaries: flags, asset
    names, sink hosts, decisions, and hashes. It intentionally does not persist
    raw tool output or secret values.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        audit_log: AuditLog | None = None,
        max_history_items: int = 20,
    ) -> None:
        super().__init__()
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_log = audit_log
        self.max_history_items = max_history_items
        self._written_keys: set[tuple[str, str | None, str | None, str | None, str]] = set()
        self._restore_events: set[tuple[str, str | None, str, str]] = set()

    def load(self, run_id: str, task_id: str | None = None) -> SessionState:
        state = self._states.get(run_id)
        if state is not None:
            if task_id and not state.task_id:
                state.task_id = task_id
                _finalise(state)
            state.approval_scope["restore_source"] = state.approval_scope.get("restore_source", "memory")
            return state
        restored = self.restore_latest_state(run_id, task_id) or self.load_from_audit(run_id, task_id)
        if restored is not None:
            if task_id and not restored.task_id:
                restored.task_id = task_id
            self._states[run_id] = _finalise(_sanitize_state(restored, self.max_history_items))
            self._append_restore_event(self._states[run_id])
            return self._states[run_id]
        state = SessionState(new_id("state"), run_id, task_id)
        state.approval_scope["restore_source"] = "none"
        self._states[run_id] = _finalise(state)
        return state

    def restore_latest_state(self, run_id: str, task_id: str | None = None) -> SessionState | None:
        latest: SessionState | None = None
        for record in self._records():
            if record.get("run_id") != run_id:
                continue
            state = _state_from_dict(record.get("state"))
            if state:
                if task_id:
                    state.task_id = task_id
                state.approval_scope["restore_source"] = "file"
                state.approval_scope["updated_at"] = record.get("timestamp")
                latest = state
        return latest

    def load_from_audit(self, run_id: str, task_id: str | None = None) -> SessionState | None:
        if not self.audit_log:
            return None
        latest: SessionState | None = None
        for event in self.audit_log.read_events():
            if event.get("event_type") not in {"session_state_update", "session_state_persisted"}:
                continue
            payload = event.get("payload") or {}
            if payload.get("run_id") != run_id:
                continue
            state = _state_from_dict(payload.get("state") or payload)
            if state:
                if task_id:
                    state.task_id = task_id
                state.approval_scope["restore_source"] = "audit"
                state.approval_scope["updated_at"] = event.get("timestamp")
                latest = state
        return latest

    def append_state_update(
        self,
        state: SessionState,
        *,
        action_id: str | None = None,
        decision_id: str | None = None,
    ) -> dict[str, Any]:
        timestamp = str(state.approval_scope.get("updated_at") or utc_now())
        state.approval_scope["updated_at"] = timestamp
        state = _finalise(_sanitize_state(state, self.max_history_items))
        key = (state.run_id, state.task_id, action_id, decision_id, state.state_hash)
        if key in self._written_keys:
            return {"deduplicated": True, "state_hash": state.state_hash}
        self._written_keys.add(key)

        prev_state_hash = self._latest_state_hash(state.run_id, state.task_id)
        record_without_hash = {
            "schema_version": "session-state-v1",
            "record_id": new_id("srec"),
            "timestamp": timestamp,
            "run_id": state.run_id,
            "task_id": state.task_id,
            "action_id": action_id,
            "decision_id": decision_id,
            "prev_state_hash": prev_state_hash,
            "state_hash": state.state_hash,
            "state": session_state_payload(state),
            "redaction": {"secret_values": "redacted", "stored_secret_hashes": True},
        }
        record = dict(record_without_hash)
        record["record_hash"] = sha256_json(record_without_hash)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str) + "\n")
        if self.audit_log:
            self.audit_log.append(
                "session_state_persisted",
                {
                    "schema_version": record["schema_version"],
                    "record_id": record["record_id"],
                    "run_id": state.run_id,
                    "task_id": state.task_id,
                    "state_hash": state.state_hash,
                    "record_hash": record["record_hash"],
                    "state": record["state"],
                    "redaction": record["redaction"],
                },
                task_id=state.task_id,
                actor="session_state_store",
                action_id=action_id,
                decision_id=decision_id,
            )
        return record

    def update(
        self,
        action: ActionIR,
        decision: PolicyDecision,
        trace: ExecTrace | None = None,
        secret_event: SecretTaintEvent | None = None,
        *,
        run_id: str,
        task_id: str | None = None,
    ) -> SessionState:
        state = super().update(action, decision, trace, secret_event, run_id=run_id, task_id=task_id)
        self.append_state_update(state, action_id=action.action_id, decision_id=decision.decision_id)
        return state

    def _records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records

    def _latest_state_hash(self, run_id: str, task_id: str | None = None) -> str:
        latest = ""
        for record in self._records():
            if record.get("run_id") != run_id:
                continue
            if task_id and record.get("task_id") not in {task_id, None, ""}:
                continue
            latest = str(record.get("state_hash") or latest)
        return latest

    def _append_restore_event(self, state: SessionState) -> None:
        if not self.audit_log:
            return
        restore_source = str(state.approval_scope.get("restore_source") or "unknown")
        key = (state.run_id, state.task_id, restore_source, state.state_hash)
        if key in self._restore_events:
            return
        self._restore_events.add(key)
        self.audit_log.append(
            "session_state_restore",
            {
                "schema_version": "session-state-restore-v1",
                "run_id": state.run_id,
                "task_id": state.task_id,
                "session_state_id": state.session_state_id,
                "state_hash": state.state_hash,
                "restore_source": restore_source,
                "state": session_state_payload(state),
                "redaction": {"secret_values": "redacted", "stored_secret_hashes": True},
            },
            task_id=state.task_id,
            actor="session_state_store",
        )


def session_state_payload(state: SessionState) -> dict:
    _sync_secret_compat(state)
    payload = asdict(state)
    payload["touched_secret_assets"] = [str(item) for item in state.touched_secret_assets]
    payload["prior_external_sinks"] = [str(item) for item in state.prior_external_sinks]
    return payload


def _finalise(state: SessionState) -> SessionState:
    payload = asdict(state)
    payload.pop("state_hash", None)
    state.state_hash = sha256_json(payload)
    return state


def _state_from_dict(value: object) -> SessionState | None:
    if not isinstance(value, dict):
        return None
    try:
        legacy_secret_taint = bool(value.get("secret_taint", False))
        attempted = bool(value.get("attempted_secret_taint", False))
        confirmed = bool(value.get("confirmed_secret_taint", False))
        if legacy_secret_taint and not attempted and not confirmed:
            confirmed = True
        attempted_assets = [str(item) for item in value.get("attempted_secret_assets", []) if item]
        confirmed_assets = [str(item) for item in value.get("confirmed_secret_assets", []) if item]
        legacy_assets = [str(item) for item in value.get("touched_secret_assets", []) if item]
        if confirmed and not confirmed_assets:
            confirmed_assets = list(legacy_assets)
        if attempted and not attempted_assets:
            attempted_assets = list(legacy_assets)
        state = SessionState(
            session_state_id=str(value.get("session_state_id") or new_id("state")),
            run_id=str(value.get("run_id") or "run_default"),
            task_id=str(value["task_id"]) if value.get("task_id") else None,
            secret_taint=legacy_secret_taint or attempted or confirmed,
            touched_secret_assets=legacy_assets,
            untrusted_source_seen=bool(value.get("untrusted_source_seen", False)),
            package_taint=bool(value.get("package_taint", False)),
            ci_taint=bool(value.get("ci_taint", False)),
            prior_external_sinks=[str(item) for item in value.get("prior_external_sinks", []) if item],
            approval_scope=dict(value.get("approval_scope") or {}),
            last_decisions=[str(item) for item in value.get("last_decisions", []) if item],
            attempted_secret_taint=attempted,
            confirmed_secret_taint=confirmed,
            attempted_secret_assets=attempted_assets,
            confirmed_secret_assets=confirmed_assets,
            taint_confidence=str(value.get("taint_confidence") or ("confirmed" if confirmed else "attempted" if attempted else "none")),
        )
        _sync_secret_compat(state)
        return _finalise(state)
    except Exception:
        return None


def _sanitize_state(state: SessionState, max_history_items: int = 20) -> SessionState:
    _sync_secret_compat(state)
    state.attempted_secret_assets = list(dict.fromkeys(_sanitize_asset(item) for item in state.attempted_secret_assets if item))[
        -max_history_items:
    ]
    state.confirmed_secret_assets = list(dict.fromkeys(_sanitize_asset(item) for item in state.confirmed_secret_assets if item))[
        -max_history_items:
    ]
    state.touched_secret_assets = list(dict.fromkeys(_sanitize_asset(item) for item in state.touched_secret_assets if item))[
        -max_history_items:
    ]
    state.prior_external_sinks = list(dict.fromkeys(_sink_host(item) for item in state.prior_external_sinks if item))[-max_history_items:]
    state.last_decisions = [str(item) for item in state.last_decisions[-max_history_items:]]
    state.approval_scope = _sanitize_mapping(state.approval_scope)
    _sync_secret_compat(state)
    return _finalise(state)


def _secret_taint_level(
    action: ActionIR,
    decision: PolicyDecision,
    trace: ExecTrace | None,
    secret_event: SecretTaintEvent | None,
) -> str:
    if not (secret_event or action.semantic_action == "read_secret_file"):
        return "none"
    if decision.decision in {"block", "quarantine"}:
        return "attempted"
    if trace and ("secret_access" in trace.risk_observed or trace.files_read or trace.env_access):
        return "confirmed"
    if decision.decision in {"allow", "allow_in_sandbox", "sandbox_then_approval"}:
        return "confirmed"
    return "attempted"


def _sync_secret_compat(state: SessionState) -> None:
    if state.secret_taint and not state.attempted_secret_taint and not state.confirmed_secret_taint:
        state.confirmed_secret_taint = True
        state.confirmed_secret_assets.extend(state.touched_secret_assets)
    state.attempted_secret_assets = list(dict.fromkeys(str(item) for item in state.attempted_secret_assets if item))
    state.confirmed_secret_assets = list(dict.fromkeys(str(item) for item in state.confirmed_secret_assets if item))
    state.secret_taint = state.attempted_secret_taint or state.confirmed_secret_taint
    state.touched_secret_assets = list(
        dict.fromkeys([*state.attempted_secret_assets, *state.confirmed_secret_assets, *state.touched_secret_assets])
    )
    state.taint_confidence = "confirmed" if state.confirmed_secret_taint else "attempted" if state.attempted_secret_taint else "none"


def _sanitize_asset(value: object) -> str:
    text = str(value)
    if text.startswith("env:"):
        return text
    if "://" in text:
        return _sink_host(text)
    return text.split("?", 1)[0]


def _sink_host(value: object) -> str:
    text = str(value)
    if "://" in text:
        parsed = urlparse(text)
        return parsed.hostname or text.split("?", 1)[0]
    if "/" in text and not text.startswith((".", "/", "\\")):
        text = text.split("/", 1)[0]
    return text.split("?", 1)[0]


def _sanitize_mapping(value: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, item in (value or {}).items():
        key_text = str(key)
        if key_text.lower() in {"secret", "token", "password", "api_key", "value"}:
            safe[key_text] = "<REDACTED>"
        elif isinstance(item, dict):
            safe[key_text] = _sanitize_mapping(item)
        elif isinstance(item, list):
            safe[key_text] = [str(v) for v in item][-20:]
        elif isinstance(item, (str, bool, int, float)) or item is None:
            safe[key_text] = item
        else:
            safe[key_text] = str(item)
    return safe
