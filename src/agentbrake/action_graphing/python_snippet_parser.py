"""Python snippet parser for common secret-to-network patterns."""

from __future__ import annotations

import ast
import re

from ..models import ActionEdge, new_id
from .base import GraphBuildContext, GraphFragment
from .fallback_heuristic import FallbackHeuristicParser, _node


class PythonSnippetParser:
    name = "python_snippet_parser"

    def can_parse(self, ctx: GraphBuildContext) -> bool:
        return bool(_extract_python_code(ctx.action.raw_action))

    def parse(self, ctx: GraphBuildContext) -> GraphFragment:
        code = _extract_python_code(ctx.action.raw_action)
        if not code:
            return FallbackHeuristicParser().parse(ctx)
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return FallbackHeuristicParser().parse(ctx)
        reads: list[str] = []
        sinks: list[str] = []
        tainted_vars: dict[str, str] = {}
        for stmt in ast.walk(tree):
            if isinstance(stmt, ast.Assign):
                source = _read_source(stmt.value)
                if source:
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            tainted_vars[target.id] = source
                            reads.append(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript) and _call_name(node.value) == "os.environ":
                key = _subscript_string(node)
                if key:
                    reads.append(f"env:{key}")
            if isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in {"open", "pathlib.path.read_text"} or name.endswith(".read_text"):
                    arg = _first_string_arg(node)
                    if arg:
                        reads.append(arg)
                if name in {"os.getenv"} or name.endswith(".environ.get"):
                    arg = _first_string_arg(node)
                    if arg:
                        reads.append(f"env:{arg}")
                if any(
                    name.endswith(suffix)
                    for suffix in (
                        "requests.get",
                        "requests.post",
                        "requests.put",
                        "requests.request",
                        "urllib.request.urlopen",
                        "http.client.HTTPSConnection",
                        "http.client.HTTPConnection",
                        "socket.create_connection",
                    )
                ):
                    host = _host_from_call(node)
                    if host:
                        sinks.append(host)
                    if any(_contains_tainted_name(arg, tainted_vars) for arg in [*node.args, *node.keywords]):
                        reads.extend(tainted_vars.values())
                if name in {"subprocess.run", "subprocess.call", "os.system"}:
                    text = ast.unparse(node) if hasattr(ast, "unparse") else ""
                    if "curl" in text or "wget" in text:
                        sinks.extend(re.findall(r"https?://([^/\\s'\\\"]+)", text))
        nodes = []
        edges = []
        for idx, path in enumerate(reads or ([] if sinks else [ctx.action.raw_action])):
            nodes.append(
                _node(
                    ctx.action,
                    new_id("anode"),
                    "read_secret_file" if (".env" in path or path.startswith("env:")) else "read_file",
                    path,
                    path,
                    idx,
                    self.name,
                )
            )
        for sink in sinks:
            nodes.append(_node(ctx.action, new_id("anode"), "send_network_request", sink, sink, len(nodes), self.name))
        if not nodes:
            return FallbackHeuristicParser().parse(ctx)
        secret_nodes = [node for node in nodes if node.semantic_action == "read_secret_file"]
        network_nodes = [node for node in nodes if node.semantic_action == "send_network_request"]
        for src in secret_nodes:
            for dst in network_nodes:
                edges.append(
                    ActionEdge(
                        new_id("aedge"),
                        src.node_id,
                        dst.node_id,
                        "dataflow",
                        evidence_refs=[ctx.action.action_id],
                        confidence=0.85,
                        metadata={"parser": self.name},
                    )
                )
        return GraphFragment(nodes, edges, 0.85, True, self.name)


def _extract_python_code(raw: str) -> str:
    m = re.search(r"\bpython(?:3)?\s+-c\s+(['\"])(.*?)\1", raw, re.I | re.S)
    return m.group(2) if m else ""


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = _call_name(func.value)
        return f"{parent}.{func.attr}" if parent else func.attr
    return ""


def _first_string_arg(node: ast.Call) -> str:
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return ""


def _read_source(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        if name.endswith(".read"):
            owner = node.func.value if isinstance(node.func, ast.Attribute) else None
            if isinstance(owner, ast.Call) and _call_name(owner.func) == "open":
                return _first_string_arg(owner)
        if name in {"open", "pathlib.path.read_text"} or name.endswith(".read_text"):
            return _first_string_arg(node)
        if name == "Path.read_text" or name.endswith(".Path.read_text"):
            return _first_string_arg(node)
        if name in {"os.getenv"} or name.endswith(".environ.get"):
            arg = _first_string_arg(node)
            return f"env:{arg}" if arg else ""
    if isinstance(node, ast.Subscript) and _call_name(node.value) == "os.environ":
        key = _subscript_string(node)
        return f"env:{key}" if key else ""
    return ""


def _contains_tainted_name(node: ast.AST, tainted_vars: dict[str, str]) -> bool:
    target = node.value if isinstance(node, ast.keyword) else node
    return any(isinstance(item, ast.Name) and item.id in tainted_vars for item in ast.walk(target))


def _subscript_string(node: ast.Subscript) -> str:
    target = node.slice
    if isinstance(target, ast.Constant) and isinstance(target.value, str):
        return target.value
    return ""


def _host_from_call(node: ast.Call) -> str:
    text = _first_string_arg(node)
    m = re.search(r"https?://([^/\s'\"]+)", text)
    return m.group(1) if m else text
