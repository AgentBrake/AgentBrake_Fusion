"""Gateway approval/confirmation flow."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import new_id, sha256_json, utc_now


@dataclass(slots=True)
class ConfirmationRequest:
    confirmation_id: str
    trace_id: str
    action_hash: str
    plan_hash: str
    summary: str
    allowed_grants: list[str]
    created_at: str = field(default_factory=utc_now)
    status: str = "pending"
    granted: str | None = None


class GatewayConfirmationFlow:
    def __init__(self) -> None:
        self.pending: dict[str, ConfirmationRequest] = {}

    def create(self, trace_id: str, action: dict[str, Any], plan: dict[str, Any] | None = None) -> ConfirmationRequest:
        req = ConfirmationRequest(
            confirmation_id=new_id("gw_confirm"),
            trace_id=trace_id,
            action_hash=sha256_json(action),
            plan_hash=sha256_json(plan or {}),
            summary=f"{action.get('semantic_action')}: {action.get('raw_action')}",
            allowed_grants=["deny", "allow_once_sandbox_only", "allow_once_no_network", "allow_once_no_lifecycle"],
        )
        self.pending[req.confirmation_id] = req
        return req

    def answer(self, confirmation_id: str, grant: str) -> ConfirmationRequest:
        req = self.pending[confirmation_id]
        if grant not in req.allowed_grants:
            raise ValueError(f"unsupported grant: {grant}")
        req.status = "denied" if grant == "deny" else "approved"
        req.granted = grant
        return req
