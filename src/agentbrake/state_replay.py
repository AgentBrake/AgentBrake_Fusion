"""Helpers for rebuilding persistent session state from durable evidence."""

from __future__ import annotations

from pathlib import Path

from .audit import AuditLog
from .models import SessionState
from .session_state import PersistentSessionStateStore


def restore_latest_session_state(
    audit_path: str | Path,
    run_id: str,
    *,
    task_id: str | None = None,
    state_path: str | Path | None = None,
) -> SessionState | None:
    """Restore the latest known state for ``run_id`` from JSONL state or audit."""
    audit = AuditLog(audit_path)
    path = Path(state_path) if state_path is not None else Path(audit_path).with_name("session_state.jsonl")
    store = PersistentSessionStateStore(path, audit_log=audit)
    return store.restore_latest_state(run_id, task_id) or store.load_from_audit(run_id, task_id)
