"""Extract typed policy facts from AgentBrake-Fusion evidence objects."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from ..contract import IntentMatcher
from ..eval.agentdojo.fact_adapter import agentdojo_facts_from_action
from ..models import ActionGraph
from .context import PolicyEvalContext
from .facts import PolicyFact, PolicyFactSet
from .indexes import AssetIndex, SourceIndex

HIGH_RISK_ACTIONS = {
    "install_registry_dependency",
    "install_git_dependency",
    "install_tarball_dependency",
    "send_network_request",
    "publish_artifact",
    "modify_ci_pipeline",
    "modify_registry_config",
    "git_push_force",
    "invoke_destructive_mcp_tool",
}
NETWORK_ACTIONS = {
    "send_network_request",
    "install_registry_dependency",
    "install_git_dependency",
    "install_tarball_dependency",
    "publish_artifact",
}


class FactExtractor:
    def __init__(self) -> None:
        self.matcher = IntentMatcher()

    def extract(self, ctx: PolicyEvalContext) -> PolicyFactSet:
        facts: list[PolicyFact] = []
        action = ctx.action
        source_index = SourceIndex(ctx.context_graph)
        asset_index = AssetIndex(ctx.asset_graph)
        intent = self.matcher.match(ctx.contract, action)
        source_summary = source_index.facts_for(action.source_ids)
        if action.metadata.get("source_has_untrusted"):
            source_summary["has_untrusted"] = True
            source_summary["trust_floor"] = "untrusted"

        facts.extend(
            [
                PolicyFact.of("action", "semantic_action", action.semantic_action, evidence_refs=[action.action_id]),
                PolicyFact.of("action", "risk", action.risk, evidence_refs=[action.action_id]),
                PolicyFact.of("action", "tool", action.tool, evidence_refs=[action.action_id]),
                PolicyFact.of("action", "side_effect", action.side_effect, evidence_refs=[action.action_id]),
                PolicyFact.of(
                    "action",
                    "parser_confidence",
                    action.parser_confidence,
                    evidence_refs=[action.action_id],
                    confidence=action.parser_confidence,
                ),
                PolicyFact.of("action", "high_risk", action.semantic_action in HIGH_RISK_ACTIONS, evidence_refs=[action.action_id]),
                PolicyFact.of("action", "network_capability", action.semantic_action in NETWORK_ACTIONS, evidence_refs=[action.action_id]),
                PolicyFact.of("source", "trust_floor", source_summary["trust_floor"], evidence_refs=action.source_ids),
                PolicyFact.of("source", "has_untrusted", source_summary["has_untrusted"], evidence_refs=action.source_ids),
                PolicyFact.of("contract", "match", intent.contract_match, evidence_refs=[ctx.contract.task_id]),
                PolicyFact.of("contract", "violation_reason", intent.violation_reason, evidence_refs=[ctx.contract.task_id]),
            ]
        )
        for tag in action.risk_tags:
            facts.append(PolicyFact.of("action", "risk_tag", tag, evidence_refs=[action.action_id]))
        facts.extend(agentdojo_facts_from_action(action))

        graph = _action_graph_from_metadata(action.metadata.get("action_graph"))
        if graph:
            graph_refs = [graph.graph_id, action.action_id]
            has_dataflow = any(edge.relation in {"pipe", "redirect", "dataflow"} for edge in graph.edges)
            has_memoryflow = any(edge.relation == "memoryflow" for edge in graph.edges)
            has_pipe = any(edge.relation == "pipe" for edge in graph.edges)
            has_redirect = any(edge.relation == "redirect" for edge in graph.edges)
            has_package_lifecycle_edge = any(
                edge.relation == "controlflow"
                and any(node.node_id == edge.dst_node_id and node.semantic_action == "run_package_lifecycle_script" for node in graph.nodes)
                for edge in graph.edges
            )
            has_sequence = len(graph.nodes) > 1 or any(edge.relation in {"sequence", "controlflow"} for edge in graph.edges)
            confidence_values = [node.confidence for node in graph.nodes] + [edge.confidence for edge in graph.edges]
            facts.extend(
                [
                    PolicyFact.of(
                        "graph", "has_dataflow_edge", has_dataflow, evidence_refs=graph_refs, metadata={"edge_count": len(graph.edges)}
                    ),
                    PolicyFact.of(
                        "graph", "has_memoryflow_edge", has_memoryflow, evidence_refs=graph_refs, metadata={"edge_count": len(graph.edges)}
                    ),
                    PolicyFact.of("graph", "has_pipe_edge", has_pipe, evidence_refs=graph_refs, metadata={"edge_count": len(graph.edges)}),
                    PolicyFact.of(
                        "graph", "has_redirect_edge", has_redirect, evidence_refs=graph_refs, metadata={"edge_count": len(graph.edges)}
                    ),
                    PolicyFact.of(
                        "graph",
                        "has_package_lifecycle_edge",
                        has_package_lifecycle_edge,
                        evidence_refs=graph_refs,
                        metadata={"edge_count": len(graph.edges)},
                    ),
                    PolicyFact.of(
                        "graph", "has_sequence", has_sequence, evidence_refs=graph_refs, metadata={"node_count": len(graph.nodes)}
                    ),
                    PolicyFact.of("graph", "node_count", len(graph.nodes), evidence_refs=graph_refs),
                    PolicyFact.of("graph", "edge_count", len(graph.edges), evidence_refs=graph_refs),
                    PolicyFact.of("graph", "complete", graph.complete, evidence_refs=graph_refs),
                    PolicyFact.of(
                        "graph",
                        "confidence_min",
                        min(confidence_values) if confidence_values else 1.0,
                        evidence_refs=graph_refs,
                        metadata={"parser": graph.metadata.get("parser")},
                    ),
                    PolicyFact.of("flow", "secret_to_external", _graph_secret_to_external(graph), evidence_refs=graph_refs),
                    PolicyFact.of(
                        "flow",
                        "secret_to_network_reachable",
                        _graph_secret_to_external(graph),
                        evidence_refs=graph_refs,
                        metadata={"source": "action_graph"},
                    ),
                    PolicyFact.of(
                        "flow",
                        "secret_to_package_script_reachable",
                        _graph_secret_to_package_script(graph),
                        evidence_refs=graph_refs,
                        metadata={"source": "action_graph"},
                    ),
                    PolicyFact.of(
                        "flow",
                        "package_script_to_network",
                        _graph_package_script_to_network(graph),
                        evidence_refs=graph_refs,
                        metadata={"source": "action_graph"},
                    ),
                    PolicyFact.of(
                        "flow",
                        "package_script_access_env",
                        _graph_package_script_access_env(graph),
                        evidence_refs=graph_refs,
                        metadata={"source": "action_graph"},
                    ),
                    PolicyFact.of(
                        "flow",
                        "trace_secret_to_network",
                        bool(graph.metadata.get("trace_enriched")) and _graph_secret_to_external(graph),
                        evidence_refs=graph_refs,
                        metadata={"source": "action_graph"},
                    ),
                    PolicyFact.of(
                        "flow",
                        "trace_env_to_network",
                        bool(graph.metadata.get("trace_enriched")) and _graph_env_to_network(graph),
                        evidence_refs=graph_refs,
                        metadata={"source": "action_graph"},
                    ),
                    PolicyFact.of(
                        "flow",
                        "untrusted_to_high_risk_reachable",
                        source_summary["has_untrusted"] and action.semantic_action in HIGH_RISK_ACTIONS,
                        evidence_refs=[*graph_refs, *action.source_ids],
                        metadata={"source": "context_graph"},
                    ),
                    PolicyFact.of(
                        "trace",
                        "enriched_graph",
                        bool(graph.metadata.get("trace_enriched")),
                        evidence_refs=graph_refs,
                        metadata={"parser": graph.metadata.get("parser")},
                    ),
                    PolicyFact.of(
                        "graph",
                        "exec_trace_enriched",
                        bool(graph.metadata.get("trace_enriched")),
                        evidence_refs=graph_refs,
                        metadata={"parser": graph.metadata.get("parser")},
                    ),
                ]
            )

        touched = self._touched_paths(ctx)
        for path in touched:
            classified = asset_index.classify_path(path)
            asset = classified["asset"]
            refs = [action.action_id]
            if asset:
                refs.append(asset.asset_id)
            forbidden = asset_index.forbidden_match(classified["path"], ctx.contract.forbidden_files)
            asset_type = classified["asset_type"] or ("forbidden_file" if forbidden else "unknown")
            facts.extend(
                [
                    PolicyFact.of("asset", "touched_path", classified["path"], evidence_refs=refs),
                    PolicyFact.of("asset", "touched_type", asset_type, evidence_refs=refs, metadata={"path": classified["path"]}),
                    PolicyFact.of(
                        "asset", "touched_risk", classified["asset_risk"], evidence_refs=refs, metadata={"path": classified["path"]}
                    ),
                    PolicyFact.of(
                        "asset",
                        "repo_escape",
                        classified["repo_escape"] or "path_escape_repo_root" in action.risk_tags,
                        evidence_refs=refs,
                        metadata={"path": classified["path"]},
                    ),
                    PolicyFact.of(
                        "asset",
                        "symlink_escape",
                        classified["symlink_escape"] or "symlink_escape_repo_root" in action.risk_tags,
                        evidence_refs=refs,
                        metadata={"path": classified["path"]},
                    ),
                    PolicyFact.of("contract", "forbidden_file_touch", forbidden, evidence_refs=refs, metadata={"path": classified["path"]}),
                ]
            )

        if ctx.package_event:
            pkg = ctx.package_event
            refs = [pkg.package_event_id, action.action_id]
            facts.extend(
                [
                    PolicyFact.of("package", "source", pkg.source, evidence_refs=refs),
                    PolicyFact.of("package", "registry", pkg.registry, evidence_refs=refs),
                    PolicyFact.of("package", "risk", pkg.risk, evidence_refs=refs),
                    PolicyFact.of(
                        "package",
                        "lifecycle_scripts",
                        bool(pkg.lifecycle_scripts),
                        evidence_refs=refs,
                        metadata={"scripts": pkg.lifecycle_scripts},
                    ),
                    PolicyFact.of("package", "reason_codes", pkg.reason_codes, evidence_refs=refs),
                ]
            )

        if ctx.secret_event:
            sec = ctx.secret_event
            refs = [sec.secret_event_id, action.action_id]
            facts.extend(
                [
                    PolicyFact.of("secret", "event", sec.event, evidence_refs=refs),
                    PolicyFact.of("secret", "asset", sec.asset, evidence_refs=refs),
                    PolicyFact.of("secret", "egress_target", sec.egress_target, evidence_refs=refs),
                ]
            )

        if ctx.exec_trace:
            trace = ctx.exec_trace
            refs = [trace.exec_trace_id, action.action_id]
            facts.extend(
                [
                    PolicyFact.of(
                        "sandbox",
                        "network_attempts",
                        bool(trace.network_attempts),
                        evidence_refs=refs,
                        metadata={"network_attempts": trace.network_attempts},
                    ),
                    PolicyFact.of(
                        "sandbox",
                        "package_scripts",
                        bool(trace.package_scripts),
                        evidence_refs=refs,
                        metadata={"package_scripts": trace.package_scripts},
                    ),
                    PolicyFact.of("sandbox", "risk_observed", trace.risk_observed, evidence_refs=refs),
                    PolicyFact.of(
                        "exec",
                        "network_attempts",
                        bool(trace.network_attempts),
                        evidence_refs=refs,
                        metadata={"network_attempts": trace.network_attempts},
                    ),
                    PolicyFact.of(
                        "exec",
                        "package_scripts",
                        bool(trace.package_scripts),
                        evidence_refs=refs,
                        metadata={"package_scripts": trace.package_scripts},
                    ),
                    PolicyFact.of("exec", "trace_scope", trace.metadata.get("trace_scope", "current_action"), evidence_refs=refs),
                ]
            )
            for item in trace.files_read:
                facts.append(PolicyFact.of("sandbox", "file_read", item, evidence_refs=refs))
            for item in trace.files_written:
                facts.append(PolicyFact.of("sandbox", "file_written", item, evidence_refs=refs))
            for item in trace.env_access:
                facts.append(PolicyFact.of("sandbox", "env_access", item, evidence_refs=refs))

        mcp_decision = action.metadata.get("mcp_decision")
        if action.semantic_action in {"invoke_mcp_tool", "invoke_destructive_mcp_tool"} or mcp_decision:
            facts.extend(
                [
                    PolicyFact.of("mcp", "decision", mcp_decision, evidence_refs=[action.action_id]),
                    PolicyFact.of(
                        "mcp",
                        "capability",
                        action.metadata.get("mcp_capability") or action.semantic_action,
                        evidence_refs=[action.action_id],
                    ),
                    PolicyFact.of("mcp", "reason_codes", action.metadata.get("mcp_reason_codes", []), evidence_refs=[action.action_id]),
                ]
            )

        if action.metadata.get("memory_authorization_denied"):
            facts.append(
                PolicyFact.of(
                    "memory",
                    "authorization_denied",
                    True,
                    evidence_refs=[action.action_id],
                    metadata={"denials": action.metadata["memory_authorization_denied"]},
                )
            )

        if ctx.session_state:
            state = ctx.session_state
            refs = [state.session_state_id, action.action_id]
            attempted_taint = bool(state.attempted_secret_taint)
            confirmed_taint = bool(state.confirmed_secret_taint)
            if state.secret_taint and not attempted_taint and not confirmed_taint:
                confirmed_taint = True
            taint_level = "confirmed" if confirmed_taint else "attempted" if attempted_taint else "none"
            if state.taint_confidence in {"attempted", "confirmed"}:
                taint_level = state.taint_confidence
            facts.extend(
                [
                    PolicyFact.of(
                        "history", "secret_taint", state.secret_taint, evidence_refs=refs, metadata={"state_hash": state.state_hash}
                    ),
                    PolicyFact.of(
                        "history", "attempted_secret_taint", attempted_taint, evidence_refs=refs, metadata={"state_hash": state.state_hash}
                    ),
                    PolicyFact.of(
                        "history", "confirmed_secret_taint", confirmed_taint, evidence_refs=refs, metadata={"state_hash": state.state_hash}
                    ),
                    PolicyFact.of(
                        "history", "secret_taint_level", taint_level, evidence_refs=refs, metadata={"state_hash": state.state_hash}
                    ),
                    PolicyFact.of(
                        "history",
                        "untrusted_seen",
                        state.untrusted_source_seen,
                        evidence_refs=refs,
                        metadata={"state_hash": state.state_hash},
                    ),
                    PolicyFact.of(
                        "history", "package_taint", state.package_taint, evidence_refs=refs, metadata={"state_hash": state.state_hash}
                    ),
                    PolicyFact.of("history", "ci_taint", state.ci_taint, evidence_refs=refs, metadata={"state_hash": state.state_hash}),
                    PolicyFact.of(
                        "history",
                        "approval_scope",
                        bool(state.approval_scope),
                        evidence_refs=refs,
                        metadata={"approval_scope": state.approval_scope, "state_hash": state.state_hash},
                    ),
                    PolicyFact.of(
                        "history",
                        "loaded_from_persistent",
                        state.approval_scope.get("restore_source") in {"file", "audit"},
                        evidence_refs=refs,
                        metadata={"restore_source": state.approval_scope.get("restore_source", "memory"), "state_hash": state.state_hash},
                    ),
                    PolicyFact.of(
                        "history",
                        "state_hash",
                        state.state_hash,
                        evidence_refs=refs,
                        metadata={"restore_source": state.approval_scope.get("restore_source", "memory")},
                    ),
                    PolicyFact.of(
                        "history",
                        "restore_source",
                        state.approval_scope.get("restore_source", "memory"),
                        evidence_refs=refs,
                        metadata={"state_hash": state.state_hash},
                    ),
                    PolicyFact.of(
                        "history",
                        "state_age_seconds",
                        _state_age_seconds(state.approval_scope.get("updated_at")),
                        evidence_refs=refs,
                        metadata={"state_hash": state.state_hash, "updated_at": state.approval_scope.get("updated_at")},
                    ),
                    PolicyFact.of(
                        "flow",
                        "secret_to_network_reachable",
                        confirmed_taint and action.semantic_action in NETWORK_ACTIONS,
                        evidence_refs=refs,
                        metadata={"source": "session_state"},
                    ),
                    PolicyFact.of(
                        "flow",
                        "attempted_secret_to_network_reachable",
                        attempted_taint and not confirmed_taint and action.semantic_action in NETWORK_ACTIONS,
                        evidence_refs=refs,
                        metadata={"source": "session_state"},
                    ),
                    PolicyFact.of(
                        "flow",
                        "secret_to_package_script_reachable",
                        confirmed_taint and state.package_taint,
                        evidence_refs=refs,
                        metadata={"source": "session_state"},
                    ),
                    PolicyFact.of(
                        "flow",
                        "untrusted_to_high_risk_reachable",
                        state.untrusted_source_seen and action.semantic_action in HIGH_RISK_ACTIONS,
                        evidence_refs=refs,
                        metadata={"source": "session_state"},
                    ),
                ]
            )
            for asset in state.attempted_secret_assets:
                facts.append(
                    PolicyFact.of("history", "attempted_secret_asset", asset, evidence_refs=refs, metadata={"state_hash": state.state_hash})
                )
            for asset in state.confirmed_secret_assets:
                facts.append(
                    PolicyFact.of("history", "confirmed_secret_asset", asset, evidence_refs=refs, metadata={"state_hash": state.state_hash})
                )
            for sink in state.prior_external_sinks:
                facts.append(
                    PolicyFact.of("history", "prior_external_sink", sink, evidence_refs=refs, metadata={"state_hash": state.state_hash})
                )

        facts.append(PolicyFact.of("policy", "eval_context", asdict(ctx), evidence_refs=[action.action_id], metadata={"phase": ctx.phase}))
        return PolicyFactSet(facts)

    @staticmethod
    def _touched_paths(ctx: PolicyEvalContext) -> list[str]:
        paths: list[str] = list(ctx.action.affected_assets)
        if ctx.secret_event and ctx.secret_event.asset:
            paths.append(ctx.secret_event.asset)
        if ctx.exec_trace:
            paths.extend(ctx.exec_trace.files_read)
            paths.extend(ctx.exec_trace.files_written)
            paths.extend([f"env:{name}" if not str(name).startswith("env:") else str(name) for name in ctx.exec_trace.env_access])
        return list(dict.fromkeys([p for p in paths if p]))


def _action_graph_from_metadata(value: object) -> ActionGraph | None:
    if not isinstance(value, dict):
        return None
    try:
        from ..models import ActionEdge, ActionNode

        return ActionGraph(
            graph_id=str(value["graph_id"]),
            run_id=str(value.get("run_id") or "run_default"),
            root_action_id=str(value.get("root_action_id") or ""),
            raw_action_hash=str(value.get("raw_action_hash") or ""),
            nodes=[ActionNode(**node) for node in value.get("nodes", [])],
            edges=[ActionEdge(**edge) for edge in value.get("edges", [])],
            parser_version=str(value.get("parser_version") or "action-graph-v1"),
            complete=bool(value.get("complete", True)),
            metadata=dict(value.get("metadata") or {}),
        )
    except Exception:
        return None


def _graph_secret_to_external(graph: ActionGraph) -> bool:
    secret_nodes = {
        node.node_id
        for node in graph.nodes
        if node.semantic_action in {"read_secret_file", "read_secret_env"}
        or any(
            "secret" in str(asset).lower() or ".env" in str(asset).lower() or str(asset).startswith("env:")
            for asset in node.affected_assets
        )
    }
    network_nodes = {
        node.node_id
        for node in graph.nodes
        if node.semantic_action == "send_network_request" or any(str(tag).startswith(("http", "attacker")) for tag in [node.target])
    }
    if not secret_nodes or not network_nodes:
        return False
    adjacency: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.relation in {"pipe", "redirect", "dataflow", "memoryflow", "controlflow"}:
            adjacency.setdefault(edge.src_node_id, set()).add(edge.dst_node_id)
    frontier = list(secret_nodes)
    seen = set(frontier)
    while frontier:
        node = frontier.pop(0)
        if node in network_nodes:
            return True
        for nxt in adjacency.get(node, set()):
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    return False


def _graph_secret_to_package_script(graph: ActionGraph) -> bool:
    secret_nodes = {
        node.node_id
        for node in graph.nodes
        if node.semantic_action in {"read_secret_file", "read_secret_env"}
        or any(
            "secret" in str(asset).lower() or ".env" in str(asset).lower() or str(asset).startswith("env:")
            for asset in node.affected_assets
        )
    }
    script_nodes = {node.node_id for node in graph.nodes if node.semantic_action == "run_package_lifecycle_script"}
    if not secret_nodes or not script_nodes:
        return False
    adjacency: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.relation in {"pipe", "redirect", "dataflow", "memoryflow", "controlflow", "sequence"}:
            adjacency.setdefault(edge.src_node_id, set()).add(edge.dst_node_id)
            if edge.relation == "controlflow":
                adjacency.setdefault(edge.dst_node_id, set()).add(edge.src_node_id)
    frontier = list(secret_nodes)
    seen = set(frontier)
    while frontier:
        node = frontier.pop(0)
        if node in script_nodes:
            return True
        for nxt in adjacency.get(node, set()):
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    return False


def _graph_package_script_to_network(graph: ActionGraph) -> bool:
    script_nodes = {node.node_id for node in graph.nodes if node.semantic_action == "run_package_lifecycle_script"}
    network_nodes = {node.node_id for node in graph.nodes if node.semantic_action == "send_network_request"}
    return _reachable(graph, script_nodes, network_nodes)


def _graph_package_script_access_env(graph: ActionGraph) -> bool:
    script_nodes = {node.node_id for node in graph.nodes if node.semantic_action == "run_package_lifecycle_script"}
    env_nodes = {node.node_id for node in graph.nodes if node.semantic_action == "read_secret_env"}
    return _reachable(graph, script_nodes, env_nodes) or _reachable(graph, env_nodes, script_nodes)


def _graph_env_to_network(graph: ActionGraph) -> bool:
    env_nodes = {node.node_id for node in graph.nodes if node.semantic_action == "read_secret_env"}
    network_nodes = {node.node_id for node in graph.nodes if node.semantic_action == "send_network_request"}
    return _reachable(graph, env_nodes, network_nodes)


def _reachable(graph: ActionGraph, sources: set[str], targets: set[str]) -> bool:
    if not sources or not targets:
        return False
    adjacency: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.relation in {"pipe", "redirect", "dataflow", "memoryflow", "controlflow", "sequence"}:
            adjacency.setdefault(edge.src_node_id, set()).add(edge.dst_node_id)
    frontier = list(sources)
    seen = set(frontier)
    while frontier:
        node = frontier.pop(0)
        if node in targets:
            return True
        for nxt in adjacency.get(node, set()):
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    return False


def _state_age_seconds(updated_at: object) -> int:
    if not updated_at:
        return 0
    try:
        text = str(updated_at)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        updated = datetime.fromisoformat(text)
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        return max(0, int((datetime.now(timezone.utc) - updated.astimezone(timezone.utc)).total_seconds()))
    except ValueError:
        return 0
