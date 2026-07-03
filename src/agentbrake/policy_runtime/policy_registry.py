"""Small YAML-free policy registry for demo policy packs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class PolicyPack:
    name: str
    policies: list[str]
    mode: str = "enforce"
    description: str = ""


class PolicyRegistry:
    def __init__(self) -> None:
        self.packs: dict[str, PolicyPack] = {}
        self.roles: dict[str, dict[str, str]] = {
            "local_dev_strict": {"core": "enforce", "gateway": "enforce", "supply_chain": "enforce", "secret_egress": "enforce"},
            "benchmark_observe": {"core": "observe_only", "gateway": "observe_only"},
            "release_guard": {"core": "enforce", "ci_cd": "enforce", "publish": "enforce"},
        }

    def register(self, pack: PolicyPack) -> None:
        self.packs[pack.name] = pack

    def mode_for(self, role: str, pack_name: str = "core") -> str:
        return self.roles.get(role, self.roles["local_dev_strict"]).get(pack_name, "enforce")

    def as_dict(self) -> dict:
        return {"packs": {k: v.__dict__ for k, v in self.packs.items()}, "roles": self.roles}
