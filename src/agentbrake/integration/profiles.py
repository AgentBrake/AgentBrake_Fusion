"""Integration profiles for quick, standard, and full agent onboarding."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from typing import Any

SUPPORTED_AGENTS = (
    "generic",
    "custom-openai",
    "custom-openai-compatible",
    "codex",
    "codex-cli",
    "claude-code",
    "cursor",
    "cline",
    "openclaw",
    "openhands",
    "aider",
)
SUPPORTED_MODES = ("quick", "standard", "full")
SHIM_COMMANDS = ("bash", "sh", "python", "python3", "pip", "pip3", "npm", "npx", "pnpm", "yarn", "git", "curl")
DEFAULT_STABLE_IDENTITY_CHANNELS = (
    "metadata.agentbrake_run_id",
    "metadata.conversation_id",
    "X-AgentBrake-Fusion-Run-Id",
)


@dataclass(frozen=True, slots=True)
class AgentProfile:
    agent: str
    display_name: str
    protocol: str
    wire_api: str
    model: str = "AgentBrake-Fusion/local-heuristic"
    api_key_env: str = "AGENTBRAKE_GATEWAY_API_KEY"
    api_key_value: str = "agentbrake-fusion-local"
    requires_authorization: bool = True
    supports_base_url: bool = True
    supports_headers: bool = True
    stable_identity_channels: tuple[str, ...] = DEFAULT_STABLE_IDENTITY_CHANNELS
    config_files: tuple[str, ...] = ()
    smoke_prompt: str = "只回复 OK，不要运行任何命令。"
    config_apply: str = "snippet"
    restore: str = "manifest"
    real_agent_command: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def smoke_endpoint(self) -> str:
        return "/v1/responses" if self.wire_api == "responses" else "/v1/chat/completions"


@dataclass(frozen=True, slots=True)
class IntegrationProfile:
    agent: str
    mode: str
    agent_profile: AgentProfile
    guarded_tools: bool
    shims: bool
    studio: bool
    approval_api: bool
    demo_package: bool

    @property
    def expected_capabilities(self) -> list[str]:
        capabilities = [
            "model_response",
            "openai_tool_calls",
            "gateway",
            "stable_session_identity",
            "audit_log",
            "agent_env",
            "agent_instructions",
            f"protocol:{self.agent_profile.wire_api}",
        ]
        if self.guarded_tools:
            capabilities.extend(["guarded_tool_shims", "file_guard", "exec_guard", "package_install", "mcp_tool"])
        if self.studio:
            capabilities.append("studio")
        if self.approval_api:
            capabilities.append("approval_api")
        if self.demo_package:
            capabilities.extend(["demo_package", "audit_evidence_graph"])
        return capabilities


def make_profile(agent: str, mode: str) -> IntegrationProfile:
    normalized_agent = _normalize_agent(agent)
    normalized_mode = mode.strip().lower()
    if normalized_agent not in AGENT_PROFILES:
        raise ValueError(f"unsupported agent: {agent}")
    if normalized_mode not in SUPPORTED_MODES:
        raise ValueError(f"unsupported integration mode: {mode}")
    return IntegrationProfile(
        agent=normalized_agent,
        mode=normalized_mode,
        agent_profile=AGENT_PROFILES[normalized_agent],
        guarded_tools=normalized_mode in {"standard", "full"},
        shims=normalized_mode in {"standard", "full"},
        studio=normalized_mode == "full",
        approval_api=normalized_mode == "full",
        demo_package=normalized_mode == "full",
    )


def _normalize_agent(agent: str) -> str:
    normalized = agent.strip().lower()
    aliases = {
        "custom": "custom-openai",
        "custom-openai-compatible": "custom-openai",
        "openai-compatible": "custom-openai",
        "codex-cli": "codex",
    }
    return aliases.get(normalized, normalized)


def agent_choices() -> tuple[str, ...]:
    return tuple(dict.fromkeys((*SUPPORTED_AGENTS, *AGENT_PROFILES)))


def profile_for_agent(agent: str) -> AgentProfile:
    return AGENT_PROFILES[_normalize_agent(agent)]


def profile_matrix() -> dict[str, dict[str, Any]]:
    return {
        name: {
            "agent": profile.agent,
            "display_name": profile.display_name,
            "protocol": profile.protocol,
            "wire_api": profile.wire_api,
            "model": profile.model,
            "api_key_env": profile.api_key_env,
            "requires_authorization": profile.requires_authorization,
            "supports_base_url": profile.supports_base_url,
            "supports_headers": profile.supports_headers,
            "stable_identity_channels": list(profile.stable_identity_channels),
            "config_files": list(profile.config_files),
            "smoke_endpoint": profile.smoke_endpoint,
            "config_apply": profile.config_apply,
            "restore": profile.restore,
            "real_agent_command": list(profile.real_agent_command),
            "maturity": _maturity_for(profile),
            "notes": list(profile.notes),
        }
        for name, profile in sorted(AGENT_PROFILES.items())
    }


def integration_matrix() -> list[dict[str, Any]]:
    return [
        {
            "agent": profile.agent,
            "wire_api": profile.wire_api,
            "smoke_endpoint": profile.smoke_endpoint,
            "config_apply": profile.config_apply,
            "restore": profile.restore,
            "real_agent_verified": bool(profile.real_agent_command),
            "maturity": _maturity_for(profile),
        }
        for profile in sorted(AGENT_PROFILES.values(), key=lambda item: item.agent)
    ]


def _maturity_for(profile: AgentProfile) -> str:
    if profile.config_apply == "native" and profile.real_agent_command:
        return "native"
    if profile.config_apply in {"native", "snippet"}:
        return "standard"
    return "documented"


def _load_profiles() -> dict[str, AgentProfile]:
    loaded = _load_yaml_profiles()
    return loaded or _fallback_profiles()


def _load_yaml_profiles() -> dict[str, AgentProfile]:
    try:
        import yaml

        root = files("agentbrake.integration").joinpath("profiles")
        result: dict[str, AgentProfile] = {}
        for entry in root.iterdir():
            if not entry.name.endswith((".yaml", ".yml")):
                continue
            data = yaml.safe_load(entry.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict):
                continue
            profile = _profile_from_mapping(data)
            result[profile.agent] = profile
        return result
    except Exception:
        return {}


def _profile_from_mapping(data: dict[str, Any]) -> AgentProfile:
    return AgentProfile(
        agent=str(data["agent"]),
        display_name=str(data.get("display_name") or data["agent"]),
        protocol=str(data.get("protocol") or "openai-compatible"),
        wire_api=str(data.get("wire_api") or "chat"),
        model=str(data.get("model") or "AgentBrake-Fusion/local-heuristic"),
        api_key_env=str(data.get("api_key_env") or "AGENTBRAKE_GATEWAY_API_KEY"),
        api_key_value=str(data.get("api_key_value") or "agentbrake-fusion-local"),
        requires_authorization=bool(data.get("requires_authorization", True)),
        supports_base_url=bool(data.get("supports_base_url", True)),
        supports_headers=bool(data.get("supports_headers", True)),
        stable_identity_channels=tuple(data.get("stable_identity_channels") or DEFAULT_STABLE_IDENTITY_CHANNELS),
        config_files=tuple(data.get("config_files") or ()),
        smoke_prompt=str(data.get("smoke_prompt") or "只回复 OK，不要运行任何命令。"),
        config_apply=str(data.get("config_apply") or "snippet"),
        restore=str(data.get("restore") or "manifest"),
        real_agent_command=tuple(data.get("real_agent_command") or ()),
        notes=tuple(data.get("notes") or ()),
    )


def _fallback_profiles() -> dict[str, AgentProfile]:
    return {
        "generic": AgentProfile(
            agent="generic",
            display_name="Generic OpenAI-compatible Agent",
            protocol="openai-compatible",
            wire_api="chat",
            config_files=(".agentbrake/agent.env", ".agentbrake/agent-instructions.md"),
            notes=("Use OPENAI_BASE_URL and OPENAI_API_KEY from .agentbrake/agent.env.",),
        ),
        "custom-openai": AgentProfile(
            agent="custom-openai",
            display_name="Custom OpenAI-compatible Agent",
            protocol="openai-compatible",
            wire_api="chat",
            config_files=(".agentbrake/agent.env", ".agentbrake/agent-instructions.md"),
            notes=("Set the agent model provider base URL to AgentBrake-Fusion Gateway.",),
        ),
        "codex": AgentProfile(
            agent="codex",
            display_name="Codex CLI",
            protocol="openai-compatible",
            wire_api="responses",
            api_key_env="AGENTBRAKE_GATEWAY_API_KEY",
            config_files=("~/.codex/config.toml",),
            config_apply="native",
            real_agent_command=("codex", "exec"),
            notes=(
                "Codex CLI uses the Responses wire API.",
                "The provider must set env_key instead of embedding the API key.",
            ),
        ),
        "claude-code": AgentProfile(
            agent="claude-code",
            display_name="Claude Code compatible bridge",
            protocol="openai-compatible",
            wire_api="chat",
            config_files=(".agentbrake/agent.env",),
        ),
        "cursor": AgentProfile(
            agent="cursor",
            display_name="Cursor OpenAI-compatible endpoint",
            protocol="openai-compatible",
            wire_api="chat",
            config_files=(".agentbrake/agent.env",),
        ),
        "cline": AgentProfile(
            agent="cline",
            display_name="Cline OpenAI-compatible endpoint",
            protocol="openai-compatible",
            wire_api="chat",
            config_files=(".agentbrake/agent.env",),
        ),
        "openclaw": AgentProfile(
            agent="openclaw",
            display_name="OpenClaw",
            protocol="openai-compatible",
            wire_api="chat",
            config_files=(".agentbrake/agent.env",),
        ),
        "openhands": AgentProfile(
            agent="openhands",
            display_name="OpenHands",
            protocol="openai-compatible",
            wire_api="chat",
            config_files=(".agentbrake/agent.env",),
        ),
        "aider": AgentProfile(
            agent="aider",
            display_name="Aider",
            protocol="openai-compatible",
            wire_api="chat",
            config_files=(".agentbrake/agent.env",),
        ),
    }


AGENT_PROFILES: dict[str, AgentProfile] = _load_profiles()
