"""Stable local session bootstrap values for formal agent integration."""

from __future__ import annotations

import os
from pathlib import Path

from ..models import sha256_json


def default_conversation_id(repo_root: str | Path, agent: str) -> str:
    seed = {"repo_root": str(Path(repo_root).resolve()), "agent": agent}
    return "conv_" + sha256_json(seed).removeprefix("sha256:")[:16]


def default_run_id(repo_root: str | Path, agent: str, conversation_id: str | None = None) -> str:
    seed = {
        "repo_root": str(Path(repo_root).resolve()),
        "agent": agent,
        "conversation_id": conversation_id or default_conversation_id(repo_root, agent),
        "user": os.getenv("USERNAME") or os.getenv("USER") or "",
    }
    return "run_" + sha256_json(seed).removeprefix("sha256:")[:16]
