"""AuditLog tailing and in-memory Studio Pro index."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from .models import ActionDetail, StudioEvent
from .normalizer import build_action_detail, build_action_judgment, build_run_summaries, graph_for_run, normalize_audit_events, read_jsonl


class StudioEventIndex:
    def __init__(self, audit_path: str | Path, *, poll_interval: float = 0.5, agent_name: str = "local") -> None:
        self.audit_path = Path(audit_path)
        self.poll_interval = poll_interval
        self.agent_name = agent_name
        self._lock = threading.RLock()
        self._raw_count = -1
        self._events: list[StudioEvent] = []

    def refresh(self) -> None:
        if os.getenv("AGENTBRAKE_DISABLE_STUDIO_EVENTS", "").lower() in {"1", "true", "yes", "on"}:
            with self._lock:
                self._raw_count = 0
                self._events = []
            return
        raw = read_jsonl(self.audit_path)
        if len(raw) == self._raw_count:
            return
        events = normalize_audit_events(raw, agent_name=self.agent_name)
        with self._lock:
            self._raw_count = len(raw)
            self._events = events

    def events(self, run_id: str | None = None, limit: int = 500) -> list[dict]:
        self.refresh()
        with self._lock:
            events = self._events if not run_id else [e for e in self._events if e.run_id == run_id]
            return [e.to_dict() for e in events[-limit:]]

    def runs(self) -> list[dict]:
        self.refresh()
        with self._lock:
            return [r.to_dict() for r in build_run_summaries(self._events)]

    def run(self, run_id: str) -> dict | None:
        for run in self.runs():
            if run.get("run_id") == run_id:
                return run
        return None

    def action_detail(self, action_id: str) -> dict | None:
        self.refresh()
        with self._lock:
            detail: ActionDetail | None = build_action_detail(self._events, action_id)
            return detail.to_dict() if detail else None

    def action_judgment(self, action_id: str) -> dict | None:
        self.refresh()
        with self._lock:
            return build_action_judgment(self._events, action_id)

    def graph(self, run_id: str) -> dict:
        self.refresh()
        with self._lock:
            return graph_for_run(self._events, run_id)

    def stream(self, run_id: str | None = None, start_index: int = 0):
        sent = start_index
        while True:
            self.refresh()
            with self._lock:
                events = self._events if not run_id else [e for e in self._events if e.run_id == run_id]
                ready = [e for e in events if e.event_index >= sent]
            for event in ready:
                sent = max(sent, event.event_index + 1)
                yield event.to_dict()
            time.sleep(self.poll_interval)
