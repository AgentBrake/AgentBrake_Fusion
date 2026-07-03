"""Sandbox profiles for v0.2 preflight and execution evidence."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import ActionIR


@dataclass(slots=True)
class SandboxProfile:
    name: str
    filesystem: str
    network: str
    env: str
    applies_to: list[str]
    dry_run_only: bool = False
    allowed_hosts: list[str] = field(default_factory=list)
    masks: list[str] = field(default_factory=lambda: [".env", ".env.*", ".npmrc", ".pypirc", "~/.ssh/**", "~/.aws/**"])
    isolation_level: str = "dry_run_or_overlay"
    production_ready: bool = False


SANDBOX_PROFILES: dict[str, SandboxProfile] = {
    "read_only": SandboxProfile(
        "read_only",
        "repo_read_only",
        "deny",
        "redacted",
        ["inspect", "grep", "read_project_file"],
        isolation_level="policy_enforced_read_only",
    ),
    "edit_overlay": SandboxProfile(
        "edit_overlay",
        "overlay_write",
        "deny",
        "redacted",
        ["edit_source_file", "unknown_side_effect"],
        isolation_level="filesystem_overlay",
    ),
    "test_sandbox": SandboxProfile(
        "test_sandbox",
        "overlay_write",
        "local_only",
        "redacted",
        ["run_tests", "run_lint"],
        allowed_hosts=["localhost", "127.0.0.1"],
        isolation_level="filesystem_overlay",
    ),
    "package_preflight": SandboxProfile(
        "package_preflight",
        "overlay_write",
        "registry_allowlist",
        "no_secrets",
        ["install_registry_dependency", "install_git_dependency", "install_tarball_dependency"],
        allowed_hosts=["registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "fake-registry.local"],
        isolation_level="dry_run_or_overlay",
    ),
    "ci_dry_run": SandboxProfile(
        "ci_dry_run",
        "overlay_write",
        "fake_services",
        "fake_secrets",
        ["modify_ci_pipeline"],
        dry_run_only=True,
        allowed_hosts=["fake-registry.local", "test-api.local"],
        isolation_level="dry_run",
    ),
    "publish_dry_run": SandboxProfile(
        "publish_dry_run",
        "overlay_write",
        "fake_registry",
        "fake_token",
        ["publish_artifact", "git_push_force"],
        dry_run_only=True,
        allowed_hosts=["fake-registry.local"],
        isolation_level="dry_run",
    ),
    "mcp_dry_run": SandboxProfile(
        "mcp_dry_run",
        "no_repo_write",
        "mcp_proxy_only",
        "redacted",
        ["invoke_destructive_mcp_tool", "invoke_mcp_tool"],
        dry_run_only=True,
        isolation_level="proxy_dry_run",
    ),
}


def profile_for_action(action: ActionIR) -> SandboxProfile:
    for profile in SANDBOX_PROFILES.values():
        if action.semantic_action in profile.applies_to:
            return profile
    if action.semantic_action.startswith("install_"):
        return SANDBOX_PROFILES["package_preflight"]
    if not action.side_effect:
        return SANDBOX_PROFILES["read_only"]
    return SANDBOX_PROFILES["edit_overlay"]


def enforcement_matrix() -> dict[str, dict[str, object]]:
    return {
        name: {
            "filesystem": profile.filesystem,
            "network": profile.network,
            "env": profile.env,
            "dry_run_only": profile.dry_run_only,
            "allowed_hosts": profile.allowed_hosts,
            "masks": profile.masks,
            "isolation_level": profile.isolation_level,
            "production_ready": profile.production_ready,
            "enforced_controls": _controls_for(profile),
        }
        for name, profile in SANDBOX_PROFILES.items()
    }


def _controls_for(profile: SandboxProfile) -> list[str]:
    controls = [f"fs:{profile.filesystem}", f"net:{profile.network}", f"env:{profile.env}"]
    if profile.dry_run_only:
        controls.append("dry_run_only")
    if profile.masks:
        controls.append("secret_masks")
    if profile.allowed_hosts:
        controls.append("host_allowlist")
    return controls
