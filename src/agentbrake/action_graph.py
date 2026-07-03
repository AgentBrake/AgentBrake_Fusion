"""Compatibility entrypoint for ActionGraph construction."""

from __future__ import annotations

from .action_graphing.orchestrator import build_action_graph, ensure_action_graph

__all__ = ["build_action_graph", "ensure_action_graph"]
