"""AgentDojo defense registration and compatibility helpers."""

from __future__ import annotations

from typing import Any

from .adapters.inspect_adapter import agentbrake_agentdojo


def register_native_defense() -> dict[str, Any]:
    return {
        "defense_name": "agentbrake_toolgate",
        "load": agentbrake_agentdojo,
        "supported": False,
        "note": "AgentDojo 0.1.35 does not expose a custom defense registry, so AgentBrake-Fusion uses a pipeline wrapper.",
    }


def get_defense_manifest() -> dict[str, Any]:
    return {
        "name": "agentbrake_toolgate",
        "entrypoint": "agentbrake.eval.agentdojo.agentdojo_defense:register_native_defense",
        "mode": "pipeline_wrapper",
    }

