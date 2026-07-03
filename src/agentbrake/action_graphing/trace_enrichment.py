"""Compatibility entrypoint for action-graph trace enrichment."""

from __future__ import annotations

from .package_script_parser import enrich_with_exec_trace

__all__ = ["enrich_with_exec_trace"]
