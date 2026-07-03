"""Gateway trace/session state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import new_id, utc_now


@dataclass(slots=True)
class GatewayTrace:
    trace_id: str = field(default_factory=lambda: new_id("gw_trace"))
    session_id: str = field(default_factory=lambda: new_id("gw_sess"))
    created_at: str = field(default_factory=utc_now)
    turns: list[dict[str, Any]] = field(default_factory=list)

    def new_turn(self, kind: str, payload: dict[str, Any]) -> str:
        turn_id = new_id("turn")
        self.turns.append({"turn_id": turn_id, "kind": kind, "timestamp": utc_now(), "payload": payload})
        return turn_id
