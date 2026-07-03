"""AgentBrake-Fusion control plane orchestration."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .action_graph import ensure_action_graph
from .action_parser import ActionParser
from .asset import AssetScanner
from .audit import AuditLog
from .context import ContextProvenance
from .contract import TaskContractBuilder
from .eval.fast_mode import EvalFastModeConfig, load_eval_fast_mode_config
from .feature_flags import feature_enabled
from .mcp_proxy import MCPProxy
from .memory import MemoryStore
from .models import ActionIR, PolicyDecision, RepoAssetGraph, SourceRecord, TaskContract
from .package_guard import PackageGuard
from .policy import PolicyEngine
from .policy_config import ConfigurablePolicyOverrides
from .sandbox import SandboxRunner
from .sentry import SecretSentry
from .session_state import PersistentSessionStateStore, SessionStateStore, session_state_payload
from .telemetry.profiler import EvalProfiler


class AgentBrakeControlPlane:
    """Single façade used by CLIs, adapters and reference agent flows."""

    def __init__(
        self,
        repo_root: str | Path,
        audit_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        policy_config: str | Path | None = None,
        audit: AuditLog | None = None,
        session_state_path: str | Path | None = None,
        session_state_store: SessionStateStore | None = None,
        run_id: str | None = None,
        fast_mode: EvalFastModeConfig | None = None,
    ):
        self.repo_root = Path(repo_root).resolve()
        self.fast_mode = fast_mode or load_eval_fast_mode_config()
        self.audit = audit or AuditLog(
            audit_path or (self.repo_root / ".agentbrake" / "audit.jsonl"), buffered=self.fast_mode.audit_buffered
        )
        self.run_id = run_id or self.audit.session_id
        self.provenance = ContextProvenance()
        self.parser = ActionParser()
        self.asset_scanner = AssetScanner(self.repo_root, env=env)
        self.asset_graph: RepoAssetGraph = self.asset_scanner.scan()
        self.policy = PolicyEngine()
        self.policy.trace_mode = self.fast_mode.policy_trace_mode
        self.policy_overrides = ConfigurablePolicyOverrides.from_file(policy_config)
        self.package_guard = PackageGuard(self.repo_root)
        self.sandbox = SandboxRunner(self.repo_root)
        self.sentry = SecretSentry(self.asset_graph)
        self.mcp_proxy = MCPProxy(self.provenance)
        self.memory = MemoryStore(self.repo_root / ".agentbrake" / "memory.json")
        if session_state_store is not None:
            self.session_states = session_state_store
        elif session_state_path is not None:
            self.session_states = PersistentSessionStateStore(session_state_path, audit_log=self.audit)
        else:
            self.session_states = SessionStateStore()
        self.contract_builder = TaskContractBuilder()
        self.contract: TaskContract | None = None
        self.audit.append("asset_scan", asdict(self.asset_graph), actor="asset_scanner")

    def reset_task_context(self) -> None:
        """Start a fresh per-request task context while keeping shared repo services."""
        self.provenance = ContextProvenance()
        self.sentry = SecretSentry(self.asset_graph)
        self.mcp_proxy = MCPProxy(self.provenance)
        self.contract = None

    def ingest_source(self, source_type: str, content: str, retrieval_path: str = "", source_id: str | None = None) -> SourceRecord:
        src = self.provenance.ingest(source_type, content, retrieval_path, source_id=source_id)
        self.audit.append("source_ingested", asdict(src), actor="context_provenance", source_ids=[src.source_id])
        return src

    def build_contract(self, user_prompt: str) -> TaskContract:
        user_src = self.ingest_source("user_request", user_prompt, retrieval_path="current_user")
        contract = self.contract_builder.build(user_prompt)
        self.contract = contract
        self.audit.append(
            "task_contract", asdict(contract), task_id=contract.task_id, actor="contract_builder", source_ids=[user_src.source_id]
        )
        return contract

    def guard_action(
        self,
        raw_action: str,
        source_ids: list[str] | None = None,
        tool: str = "Bash",
        operation: str | None = None,
        file_path: str | None = None,
        run_preflight: bool = True,
    ) -> tuple[ActionIR, PolicyDecision]:
        if self.contract is None:
            self.build_contract("general code maintenance task")
        action = self.parser.parse(
            raw_action, tool=tool, cwd=self.repo_root, source_ids=source_ids or [], operation=operation, file_path=file_path
        )
        return self.guard_action_ir(action, run_preflight=run_preflight)

    def guard_action_ir(
        self,
        action: ActionIR,
        *,
        run_preflight: bool = True,
    ) -> tuple[ActionIR, PolicyDecision]:
        """Govern an already-lowered ActionIR without reparsing raw tool input."""
        profiler = EvalProfiler()
        if self.contract is None:
            self.build_contract("general code maintenance task")
        assert self.contract is not None
        for sid in action.source_ids:
            self.provenance.influence(sid, action.action_id)
        with profiler.span("session.restore_ms"):
            state = (
                self.session_states.load(self.run_id, self.contract.task_id)
                if feature_enabled("AGENTBRAKE_ENABLE_SESSION_STATE", default=True)
                else None
            )
        action.metadata["source_has_untrusted"] = bool(
            action.metadata.get("source_has_untrusted") or self.provenance.graph.has_untrusted(action.source_ids)
        )

        with profiler.span("context.extract_ms"):
            secret_event = self.sentry.observe_action(action)
        if secret_event:
            self.audit.append(
                "secret_event", asdict(secret_event), task_id=self.contract.task_id, actor="secret_sentry", action_id=action.action_id
            )

        with profiler.span("policy.fact_extract_ms"):
            package_event = self.package_guard.analyze(action)
        if package_event:
            self.audit.append(
                "package_event", asdict(package_event), task_id=self.contract.task_id, actor="package_guard", action_id=action.action_id
            )
        build_action_graph = feature_enabled("AGENTBRAKE_ENABLE_ACTION_GRAPH", default=True) and (
            not self.fast_mode.enabled
            or self.fast_mode.evidence_graph_mode == "full"
            or action.risk in {"high", "critical"}
            or action.side_effect
        )
        if build_action_graph:
            with profiler.span("action_graph.build_ms"):
                graph = ensure_action_graph(
                    action, run_id=self.run_id, repo_root=self.repo_root, package_event=package_event, session_state=state
                )
                action.metadata["action_graph"] = asdict(graph)
            self.audit.append(
                "action_graph",
                asdict(graph),
                task_id=self.contract.task_id,
                actor="action_graph",
                source_ids=action.source_ids,
                action_id=action.action_id,
            )
        self.audit.append(
            "action_parsed",
            asdict(action),
            task_id=self.contract.task_id,
            actor="action_parser",
            source_ids=action.source_ids,
            action_id=action.action_id,
        )

        mcp_invocation = None
        if action.semantic_action in {"invoke_mcp_tool", "invoke_destructive_mcp_tool"}:
            mcp_args = (
                action.metadata.get("mcp_args") if isinstance(action.metadata.get("mcp_args"), dict) else {"raw_action": action.raw_action}
            )
            server_id = str(action.metadata.get("mcp_server_id") or "mcp_adapter")
            tool_name = str(action.metadata.get("mcp_tool_name") or action.raw_action)
            mcp_invocation = self.mcp_proxy.invoke(server_id, tool_name, mcp_args)
            action.metadata["mcp_decision"] = mcp_invocation.decision
            action.metadata["mcp_reason_codes"] = mcp_invocation.reason_codes
            self.audit.append(
                "mcp_invocation",
                asdict(mcp_invocation),
                task_id=self.contract.task_id,
                actor="mcp_proxy",
                source_ids=action.source_ids,
                action_id=action.action_id,
            )
            if mcp_invocation.output_source_id:
                self.audit.append(
                    "source_ingested",
                    {"source_id": mcp_invocation.output_source_id, "source_type": "mcp_output"},
                    task_id=self.contract.task_id,
                    actor="mcp_proxy",
                    source_ids=[mcp_invocation.output_source_id],
                    action_id=action.action_id,
                )

        if action.semantic_action == "memory_write":
            record = self.memory.write(action.raw_action, action.source_ids, self.provenance.graph, created_by="control_plane")
            self.audit.append(
                "memory_event",
                asdict(record),
                task_id=self.contract.task_id,
                actor="memory_store",
                source_ids=action.source_ids,
                action_id=action.action_id,
            )
        elif action.semantic_action == "memory_read":
            self.audit.append(
                "memory_event",
                {"event": "memory_read_requested", "raw_action_hash": action.raw_action},
                task_id=self.contract.task_id,
                actor="memory_store",
                source_ids=action.source_ids,
                action_id=action.action_id,
            )
        self._apply_memory_authorization_gate(action)

        # First decision: may already hard-block before sandbox. Preflight can enrich evidence for high-risk actions.
        trace = None
        with profiler.span("policy.total_ms"):
            decision = self.policy.decide(
                self.contract,
                action,
                self.asset_graph,
                self.provenance.graph,
                package_event=package_event,
                secret_event=secret_event,
                session_state=state,
            )
        preflight_plan = self.policy.plan_preflight(decision) if hasattr(self.policy, "plan_preflight") else None
        if self.fast_mode.disable_preflight and action.metadata.get("agentdojo") is None:
            run_preflight = False
        if run_preflight and preflight_plan and preflight_plan.required:
            trace = self.sandbox.preflight(
                action,
                decision=decision,
                package_event=package_event,
                profile=preflight_plan.profile,
                evidence_mode=preflight_plan.evidence_mode,
            )
            self.audit.append("exec_trace", asdict(trace), task_id=self.contract.task_id, actor="sandbox", action_id=action.action_id)
            if feature_enabled("AGENTBRAKE_ENABLE_ACTION_GRAPH", default=True):
                enriched_graph = ensure_action_graph(
                    action, run_id=self.run_id, repo_root=self.repo_root, exec_trace=trace, package_event=package_event, session_state=state
                )
                self.audit.append(
                    "action_graph_enriched",
                    asdict(enriched_graph),
                    task_id=self.contract.task_id,
                    actor="action_graph",
                    source_ids=action.source_ids,
                    action_id=action.action_id,
                )
            with profiler.span("policy.total_ms"):
                decision = self.policy.decide(
                    self.contract,
                    action,
                    self.asset_graph,
                    self.provenance.graph,
                    package_event=package_event,
                    secret_event=secret_event,
                    exec_trace=trace,
                    session_state=state,
                )

        if state is not None:
            with profiler.span("session.persist_ms"):
                updated = self.session_states.update(
                    action, decision, trace, secret_event, run_id=self.run_id, task_id=self.contract.task_id
                )
            self.audit.append(
                "session_state_update",
                session_state_payload(updated),
                task_id=self.contract.task_id,
                actor="session_state",
                source_ids=action.source_ids,
                action_id=action.action_id,
                decision_id=decision.decision_id,
            )

        policy_fact_events = self.policy.consume_fact_events() if hasattr(self.policy, "consume_fact_events") else []
        policy_eval_events = self.policy.consume_eval_events() if hasattr(self.policy, "consume_eval_events") else []
        decision = self.policy_overrides.apply(action, decision)
        for event in self.policy_overrides.consume_events():
            self.audit.append(
                "policy_override_event",
                event,
                task_id=self.contract.task_id,
                actor="policy_config",
                action_id=action.action_id,
                decision_id=decision.decision_id,
            )

        for event in policy_fact_events:
            self.audit.append(
                "policy_fact_set",
                event,
                task_id=self.contract.task_id,
                actor="policy_engine",
                source_ids=action.source_ids,
                action_id=action.action_id,
                decision_id=decision.decision_id,
            )
        for event in policy_eval_events:
            self.audit.append(
                "policy_eval_trace",
                event,
                task_id=self.contract.task_id,
                actor="policy_engine",
                source_ids=action.source_ids,
                action_id=action.action_id,
                decision_id=decision.decision_id,
            )
        constraint_trace = _constraint_lattice_payload(decision)
        if constraint_trace:
            self.audit.append(
                "constraint_lattice_trace",
                constraint_trace,
                task_id=self.contract.task_id,
                actor="policy_engine",
                source_ids=action.source_ids,
                action_id=action.action_id,
                decision_id=decision.decision_id,
            )
        self.audit.append(
            "policy_decision",
            asdict(decision),
            task_id=self.contract.task_id,
            actor="policy_engine",
            source_ids=action.source_ids,
            action_id=action.action_id,
            decision_id=decision.decision_id,
        )
        profiler.add(
            "gateway.total_ms",
            sum(value for key, value in profiler.timings.items() if key != "gateway.total_ms"),
        )
        self.audit.append(
            "performance_trace",
            profiler.as_event(),
            task_id=self.contract.task_id,
            actor="telemetry",
            source_ids=action.source_ids,
            action_id=action.action_id,
            decision_id=decision.decision_id,
        )
        if self.fast_mode.audit_buffered:
            self.audit.flush()
        return action, decision

    def _apply_memory_authorization_gate(self, action: ActionIR) -> None:
        use = self._authorization_use(action.semantic_action)
        if not use:
            return
        denied: list[dict[str, str]] = []
        for sid in action.source_ids:
            src = self.provenance.graph.get(sid)
            if not src or src.source_type != "memory":
                continue
            memory_id = sid.removeprefix("src_")
            ok, reason = self.memory.can_authorize(memory_id, use)
            if not ok:
                denied.append({"source_id": sid, "memory_id": memory_id, "use": use, "reason": reason})
        if denied:
            action.metadata["memory_authorization_denied"] = denied
            self.audit.append(
                "memory_event",
                {"event": "memory_authorization_denied", "denials": denied},
                task_id=self.contract.task_id if self.contract else None,
                actor="memory_store",
                source_ids=action.source_ids,
                action_id=action.action_id,
            )

    @staticmethod
    def _authorization_use(semantic_action: str) -> str | None:
        mapping = {
            "install_registry_dependency": "authorize_dependency_install",
            "install_git_dependency": "authorize_dependency_install",
            "install_tarball_dependency": "authorize_dependency_install",
            "send_network_request": "authorize_network_egress",
            "publish_artifact": "authorize_publish",
            "modify_ci_pipeline": "authorize_ci_modify",
            "modify_registry_config": "override_policy",
        }
        return mapping.get(semantic_action)

    def scan_report(self) -> dict[str, Any]:
        report = self.asset_scanner.report(self.asset_graph)
        return {"asset_graph": asdict(self.asset_graph), "risk_surface_report": asdict(report)}

    def incident_graph(self) -> dict[str, Any]:
        return self.audit.incident_graph()


def _constraint_lattice_payload(decision: PolicyDecision) -> dict[str, Any]:
    for step in reversed(decision.rule_trace):
        if isinstance(step, dict) and step.get("engine") in {"constraint_product_lattice", "constraint_lattice"}:
            return {
                "schema_version": "constraint-product-lattice-trace-v1",
                "decision_id": decision.decision_id,
                "action_id": decision.action_id,
                "mapped_decision": step.get("mapped_decision", decision.decision),
                "constraints": step.get("constraints") or {},
                "decision_model": decision.metadata.get("decision_model", "AgentBrake-Fusion/MSJ Engine"),
            }
    return {}
