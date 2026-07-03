"""Human-in-the-loop approval centre with plan/action hash binding."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import ActionIR, ApprovalGrant, ApprovalRequest, ContextGraph, ExecTrace, PolicyDecision, TaskContract, new_id, sha256_json


def stable_action_hash_v1(action: ActionIR, task_id: str | None = None) -> str:
    """Hash logical action identity without volatile parse ids."""
    return sha256_json(
        {
            "task_id": task_id,
            "raw_action_normalized": " ".join(action.raw_action.split()),
            "tool": action.tool.lower(),
            "semantic_action": action.semantic_action,
            "affected_assets": sorted(action.affected_assets),
            "source_ids": sorted(action.source_ids),
            "operation": action.metadata.get("operation"),
            "file_path": action.metadata.get("file_path") or (action.affected_assets[0] if action.affected_assets else None),
        }
    )


def stable_action_hash_v2(action: ActionIR, task_id: str | None = None) -> str:
    """Hash action identity plus optional graph binding while preserving v1 grants."""
    graph = action.metadata.get("action_graph") if isinstance(action.metadata.get("action_graph"), dict) else {}
    return sha256_json(
        {
            "v1": stable_action_hash_v1(action, task_id),
            "graph_id": action.graph_id or action.metadata.get("action_graph_id"),
            "graph_node_count": len(graph.get("nodes") or []),
            "graph_edge_relations": sorted(edge.get("relation") for edge in (graph.get("edges") or []) if isinstance(edge, dict)),
            "sequence_no": action.sequence_no,
            "parent_action_id": action.parent_action_id,
        }
    )


def stable_action_hash(action: ActionIR, task_id: str | None = None) -> str:
    return stable_action_hash_v1(action, task_id)


class ApprovalCenter:
    def __init__(self) -> None:
        self.created_requests = 0
        self.grants_issued = 0
        self.denials = 0

    def create_request(
        self,
        contract: TaskContract,
        action: ActionIR,
        decision: PolicyDecision,
        context_graph: ContextGraph,
        plan: dict[str, Any] | None = None,
        exec_trace: ExecTrace | None = None,
    ) -> ApprovalRequest:
        self.created_requests += 1
        plan_hash = sha256_json(plan or {"task_id": contract.task_id, "goal": contract.goal})
        action_hash_v1 = stable_action_hash_v1(action, contract.task_id)
        action_hash_v2 = stable_action_hash_v2(action, contract.task_id)
        source_influence = []
        for sid in action.source_ids:
            src = context_graph.get(sid)
            source_influence.append({"source_id": sid, "trust": src.trust_level if src else "unknown"})
        return ApprovalRequest(
            approval_request_id=new_id("apr_req"),
            task_id=contract.task_id,
            action_id=action.action_id,
            plan_hash=plan_hash,
            action_hash=action_hash_v1,
            human_readable_summary=f"{action.semantic_action}: {action.raw_action}",
            source_influence=source_influence,
            affected_assets=action.affected_assets,
            observed_sandbox_risks=exec_trace.risk_observed if exec_trace else [],
            recommended_decision=decision.decision,
            available_grants=[
                "deny",
                "allow_once_sandbox_only",
                "allow_once_no_network",
                "allow_once_no_lifecycle",
                "allow_temporarily_with_constraints",
            ],
            action_hash_v1=action_hash_v1,
            action_hash_v2=action_hash_v2,
        )

    def grant(
        self, request: ApprovalRequest, constraints: list[str] | None = None, minutes: int = 30, granted_by: str = "local_user"
    ) -> ApprovalGrant:
        self.grants_issued += 1
        expires = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        return ApprovalGrant(
            approval_id=new_id("appr"),
            task_id=request.task_id,
            action_id=request.action_id,
            approved_plan_hash=request.plan_hash,
            approved_action_hash=request.action_hash,
            constraints=constraints or ["sandbox_only", "no_network"],
            expires_at=expires.isoformat(timespec="seconds"),
            granted_by=granted_by,
            approved_action_hash_v1=request.action_hash_v1 or request.action_hash,
            approved_action_hash_v2=request.action_hash_v2,
        )

    def deny(self, request: ApprovalRequest) -> dict[str, str]:
        self.denials += 1
        return {"approval_request_id": request.approval_request_id, "decision": "denied"}

    def validate(
        self,
        grant: ApprovalGrant,
        action: ActionIR,
        plan: dict[str, Any] | None = None,
        contract: TaskContract | None = None,
        exec_trace: ExecTrace | None = None,
    ) -> tuple[bool, str]:
        now = datetime.now(timezone.utc)
        expires = datetime.fromisoformat(grant.expires_at)
        if now > expires:
            return False, "approval_expired"
        task_id = contract.task_id if contract else grant.task_id
        action_hash_v1 = stable_action_hash_v1(action, task_id)
        action_hash_v2 = stable_action_hash_v2(action, task_id)
        approved_hashes = {grant.approved_action_hash}
        if grant.approved_action_hash_v1:
            approved_hashes.add(grant.approved_action_hash_v1)
        if grant.approved_action_hash_v2:
            approved_hashes.add(grant.approved_action_hash_v2)
        if action_hash_v1 not in approved_hashes and action_hash_v2 not in approved_hashes:
            return False, "action_hash_mismatch"
        if plan is not None:
            plan_hash = sha256_json(plan)
            if plan_hash != grant.approved_plan_hash:
                return False, "plan_hash_mismatch"
        if contract and grant.task_id != contract.task_id:
            return False, "task_id_mismatch"
        if exec_trace:
            ok, reason = self._validate_constraints(grant.constraints, action, exec_trace)
            if not ok:
                return False, reason
        return True, "approval_valid"

    @staticmethod
    def _validate_constraints(constraints: list[str], action: ActionIR, exec_trace: ExecTrace) -> tuple[bool, str]:
        c = set(constraints)
        if "no_network" in c or "allow_once_no_network" in c:
            if exec_trace.network_attempts:
                return False, "approval_constraint_network_mismatch"
        if "no_lifecycle" in c or "allow_once_no_lifecycle" in c:
            if exec_trace.package_scripts:
                return False, "approval_constraint_lifecycle_mismatch"
        if "sandbox_only" in c or "allow_once_sandbox_only" in c:
            if exec_trace.sandbox_profile in {"", "none", "host"}:
                return False, "approval_constraint_sandbox_mismatch"
        return True, "approval_constraints_valid"

    def burden_metrics(self) -> dict[str, float | int]:
        total = self.created_requests or 1
        return {
            "created_requests": self.created_requests,
            "grants_issued": self.grants_issued,
            "denials": self.denials,
            "grant_rate": round(self.grants_issued / total, 3),
            "denial_rate": round(self.denials / total, 3),
        }


class ApprovalStore:
    """Tiny JSONL persistence layer for approval requests and grants.

    The store keeps approval memory outside process RAM while preserving the
    hash-bound request/grant objects used by ApprovalCenter.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append_request(self, request: ApprovalRequest) -> None:
        self._append("request", asdict(request))

    def append_grant(self, grant: ApprovalGrant) -> None:
        self._append("grant", asdict(grant))

    def append_denial(self, request: ApprovalRequest, denied_by: str = "local_user") -> None:
        self._append(
            "denial",
            {
                "approval_request_id": request.approval_request_id,
                "task_id": request.task_id,
                "action_id": request.action_id,
                "denied_by": denied_by,
            },
        )

    def list_events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events

    def grants_for_action(self, action: ActionIR) -> list[ApprovalGrant]:
        grants: list[ApprovalGrant] = []
        for event in self.list_events():
            if event.get("event_type") != "grant":
                continue
            payload = event.get("payload", {})
            action_hashes = {stable_action_hash_v1(action, payload.get("task_id")), stable_action_hash_v2(action, payload.get("task_id"))}
            approved_hashes = {
                payload.get("approved_action_hash"),
                payload.get("approved_action_hash_v1"),
                payload.get("approved_action_hash_v2"),
            }
            if action_hashes & {h for h in approved_hashes if h}:
                grants.append(ApprovalGrant(**payload))
        return grants

    def latest_valid_grant(self, action: ActionIR, center: ApprovalCenter | None = None, **validate_kwargs: Any) -> ApprovalGrant | None:
        validator = center or ApprovalCenter()
        for grant in reversed(self.grants_for_action(action)):
            ok, _reason = validator.validate(grant, action, **validate_kwargs)
            if ok:
                return grant
        return None

    def _append(self, event_type: str, payload: dict[str, Any]) -> None:
        event = {
            "event_type": event_type,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "payload": payload,
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
