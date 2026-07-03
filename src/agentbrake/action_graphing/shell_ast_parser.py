"""Optional bashlex-backed shell parser.

This parser is deliberately optional: when bashlex is not installed, the
orchestrator falls through to the regex ShellParser without changing runtime
dependencies.
"""

from __future__ import annotations

import re

from .base import GraphBuildContext, GraphFragment
from .shell_parser import ShellParser


class ShellAstParser:
    name = "shell_ast_parser"

    def can_parse(self, ctx: GraphBuildContext) -> bool:
        try:
            import bashlex  # noqa: F401
        except Exception:
            return False
        raw = ctx.action.raw_action
        return bool(raw) and (ctx.action.tool.lower() in {"bash", "shell", "sh"} or re.search(r"[|;$<>]|\$\(|`", raw))

    def parse(self, ctx: GraphBuildContext) -> GraphFragment:
        try:
            import bashlex

            bashlex.parser.parse(ctx.action.raw_action)
        except Exception:
            return ShellParser().parse(ctx)
        fragment = ShellParser().parse(ctx)
        fragment.parser_name = self.name
        fragment.warnings.append("bashlex_ast_available_best_effort")
        for node in fragment.nodes:
            node.metadata["parser_name"] = self.name
        for edge in fragment.edges:
            edge.metadata["parser"] = self.name
        return fragment
