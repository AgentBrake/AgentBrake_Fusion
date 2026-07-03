"""Common adapter protocol objects for external agents."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..models import PolicyDecision
from .base import AgentToolCall


@dataclass(slots=True)
class AdapterEvent:
    event_type: str
    message: str
    tool_call: AgentToolCall | None = None
    decision: PolicyDecision | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class AdapterRunResult:
    adapter: str
    repo_root: str
    task: str
    allowed: list[str] = field(default_factory=list)
    host_executed: list[str] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)
    sandboxed: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    approval_required: list[str] = field(default_factory=list)
    simulated: list[str] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    audit_log: str | None = None

    @property
    def ok(self) -> bool:
        return True


SOURCE_IDS_RE = re.compile(r"(?:^|\s)source_ids=([A-Za-z0-9_,:\-./]+)\s*$")
EXECUTABLE_LINE_RE = re.compile(
    r"(?i)\b("
    r"TOOL_CALL|assistant to=|bash|shell|terminal|cmd|powershell|npm|pnpm|yarn|npx|pip|pytest|python|git|curl|wget|cat|rm|mv|cp|docker"
    r")\b"
)


def parse_agentbrake_action_lines(text: str, default_tool: str = "Bash", *, strict: bool = False) -> list[AgentToolCall]:
    """Parse a simple generic adapter transcript.

    Supported forms:
      RS_ACTION: npm test
      RUN: npm test
      EDIT: src/login.js
      READ: README.md
      {"type":"action","raw_action":"npm test","tool":"Bash","source_ids":["src_1"]}
    """
    calls: list[AgentToolCall] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        json_call = _parse_jsonl_action(line, default_tool)
        if json_call:
            calls.append(json_call)
            continue
        upper = line.upper()
        if upper.startswith("SOURCE:"):
            continue
        if upper.startswith("RS_ACTION:") or upper.startswith("RUN:"):
            action = line.split(":", 1)[1].strip()
            if action:
                action, source_ids = _extract_source_ids(action)
                calls.append(AgentToolCall(action, default_tool, source_ids))
        elif upper.startswith("EDIT:"):
            path = line.split(":", 1)[1].strip()
            path, source_ids = _extract_source_ids(path)
            calls.append(AgentToolCall(path, "Edit", source_ids, operation="edit", file_path=path))
        elif upper.startswith("READ:"):
            path = line.split(":", 1)[1].strip()
            path, source_ids = _extract_source_ids(path)
            calls.append(AgentToolCall(path, "Read", source_ids, operation="read", file_path=path))
        elif strict and _looks_executable(line):
            calls.append(AgentToolCall(line, "Unknown", []))
    return calls


def _extract_source_ids(action: str) -> tuple[str, list[str]]:
    match = SOURCE_IDS_RE.search(action)
    if not match:
        return action.strip(), []
    source_ids = [sid for sid in match.group(1).split(",") if sid]
    return action[: match.start()].strip(), source_ids


def _parse_jsonl_action(line: str, default_tool: str) -> AgentToolCall | None:
    if not line.startswith("{"):
        return None
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if payload.get("type") != "action":
        return None
    raw_action = str(payload.get("raw_action") or payload.get("command") or payload.get("input") or "").strip()
    if not raw_action:
        return None
    source_ids = payload.get("source_ids") or []
    if not isinstance(source_ids, list):
        source_ids = [str(source_ids)]
    return AgentToolCall(
        raw_action=raw_action,
        tool=str(payload.get("tool") or default_tool),
        source_ids=[str(sid) for sid in source_ids],
        operation=payload.get("operation"),
        file_path=payload.get("file_path") or payload.get("path"),
    )


def _looks_executable(line: str) -> bool:
    return bool(EXECUTABLE_LINE_RE.search(line))


def ensure_repo(path: str | Path) -> Path:
    repo = Path(path).resolve()
    if not repo.exists():
        raise FileNotFoundError(f"repo not found: {repo}")
    return repo
