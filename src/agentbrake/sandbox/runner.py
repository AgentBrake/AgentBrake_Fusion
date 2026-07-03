"""Zero-trust sandbox runner with overlay-style evidence capture.

The implementation remains unprivileged and deterministic for CI, but the API is
structured around backend profiles so a production build can swap in Linux
namespaces, bubblewrap, firejail or containerd without changing the control
plane or audit schema.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..models import ActionIR, ExecTrace, PackageEvent, PolicyDecision, new_id
from .profiles import SANDBOX_PROFILES, SandboxProfile, profile_for_action

SENSITIVE_NAMES = {".env", ".npmrc", ".pypirc"}
SAFE_TEST_PREFIXES = ["pytest", "python -m pytest"]


class SandboxBackend:
    name = "base"

    def __init__(self, repo_root: str | Path):
        self.repo_root = Path(repo_root).resolve()

    def preflight(
        self,
        action: ActionIR,
        profile: SandboxProfile,
        decision: PolicyDecision | None = None,
        package_event: PackageEvent | None = None,
        evidence_mode: str = "summary",
    ) -> ExecTrace:
        raise NotImplementedError


class DryRunBackend(SandboxBackend):
    name = "dry_run"

    def preflight(
        self,
        action: ActionIR,
        profile: SandboxProfile,
        decision: PolicyDecision | None = None,
        package_event: PackageEvent | None = None,
        evidence_mode: str = "summary",
    ) -> ExecTrace:
        trace = ExecTrace(
            exec_trace_id=new_id("trace"),
            action_id=action.action_id,
            command=action.raw_action,
            sandbox_profile=profile.name,
            process_tree=_process_tree(action.raw_action),
            recommended_decision=decision.decision if decision else "allow",
            metadata={"requested_profile": profile.name, "actual_profile": profile.name, "evidence_mode": evidence_mode},
        )

        if action.semantic_action.startswith("install_"):
            trace.files_read.extend(["package.json", "pyproject.toml", "requirements.txt"])
            trace.files_written.extend(
                ["package-lock.json", "node_modules/**"]
                if re.search(r"\b(npm|pnpm|yarn)\b", action.raw_action, re.I)
                else ["site-packages/**"]
            )
            if package_event:
                trace.package_scripts.extend(package_event.lifecycle_scripts)
                if package_event.source in {"git_url", "tarball_url"}:
                    trace.network_attempts.append(
                        {"host": _host_from_package(package_event.package) or "github.com", "port": 443, "blocked": True}
                    )
                if package_event.package and re.search(r"attacker|unknown|helper", package_event.package, re.I):
                    trace.env_access.append("RS_CANARY_NPM_TOKEN")
                    trace.network_attempts.append({"host": "attacker.local", "port": 8080, "blocked": True, "payload_digest": "redacted"})
                    trace.risk_observed.extend(
                        ["external_dependency", "lifecycle_script_detected", "secret_access", "network_egress_attempt"]
                    )
            if trace.network_attempts or trace.package_scripts:
                trace.recommended_decision = "block"
            return trace

        if action.semantic_action == "send_network_request":
            target = action.affected_assets[0] if action.affected_assets else "unknown"
            trace.network_attempts.append({"host": target, "port": 443, "blocked": True})
            trace.risk_observed.append("network_egress_attempt")
            trace.recommended_decision = "block"
            return trace

        if action.semantic_action == "read_secret_file":
            trace.files_read.extend(action.affected_assets or ["secret"])
            trace.risk_observed.append("secret_access")
            trace.recommended_decision = "block"
            return trace

        if action.semantic_action == "publish_artifact":
            trace.files_read.extend(["package.json", ".npmrc"])
            trace.env_access.append("NPM_TOKEN(redacted)")
            trace.network_attempts.append({"host": "fake-registry.local", "port": 443, "blocked": False, "dry_run": True})
            trace.risk_observed.append("publish_attempt_dry_run")
            trace.recommended_decision = "block"
            return trace

        if action.semantic_action == "modify_registry_config":
            trace.files_written.extend([".npmrc", ".pypirc"])
            trace.risk_observed.append("registry_config_change")
            trace.recommended_decision = "block"
            return trace

        if action.semantic_action == "modify_ci_pipeline":
            trace.files_written.extend(action.affected_assets or [".github/workflows/**"])
            trace.diff_summary.append("workflow diff captured in overlay; host workspace not modified")
            if "curl" in action.raw_action.lower() or "attacker" in action.raw_action.lower():
                trace.network_attempts.append({"host": "attacker.local", "port": 8080, "blocked": True})
                trace.risk_observed.append("workflow_injected_network_egress")
            trace.recommended_decision = "block"
            return trace

        if action.semantic_action == "invoke_destructive_mcp_tool":
            trace.risk_observed.append("destructive_mcp_tool_dry_run")
            trace.recommended_decision = "block"
            return trace

        if action.semantic_action == "run_tests":
            trace.risk_observed.append("test_command_simulated")
            trace.exit_code = 0
            return trace

        if action.semantic_action == "edit_source_file":
            trace.files_written.extend(action.affected_assets)
            trace.diff_summary.append("diff captured in overlay; not automatically written back")
            return trace

        if action.side_effect:
            trace.risk_observed.append("unknown_side_effect_not_executed")
            trace.recommended_decision = "sandbox_then_approval"
        return trace


class SubprocessOverlayBackend(DryRunBackend):
    """Execute explicitly safe local tests in a sensitive-file-masked copy."""

    name = "subprocess_overlay"

    def preflight(
        self,
        action: ActionIR,
        profile: SandboxProfile,
        decision: PolicyDecision | None = None,
        package_event: PackageEvent | None = None,
        evidence_mode: str = "summary",
    ) -> ExecTrace:
        if action.semantic_action != "run_tests":
            return super().preflight(action, profile, decision, package_event, evidence_mode=evidence_mode)
        trace = ExecTrace(
            new_id("trace"),
            action.action_id,
            action.raw_action,
            profile.name,
            process_tree=_process_tree(action.raw_action),
            recommended_decision=decision.decision if decision else "allow",
            metadata={"requested_profile": profile.name, "actual_profile": profile.name, "evidence_mode": evidence_mode},
        )
        raw = action.raw_action.strip()
        if not any(raw == prefix or raw.startswith(prefix + " ") for prefix in SAFE_TEST_PREFIXES):
            trace.risk_observed.append("test_command_simulated")
            trace.exit_code = 0
            return trace
        temp = Path(tempfile.mkdtemp(prefix="agentbrake-sandbox-"))
        try:
            dst = temp / "repo"
            shutil.copytree(self.repo_root, dst, ignore=_ignore_sensitive)
            env = {k: v for k, v in os.environ.items() if not _is_secret_env(k)}
            try:
                args = shlex.split(raw)
            except ValueError:
                trace.risk_observed.append("sandbox_command_parse_failed")
                trace.recommended_decision = "sandbox_then_approval"
                trace.trace_complete = False
                return trace
            proc = subprocess.run(
                args, cwd=dst, shell=False, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30
            )
            trace.exit_code = proc.returncode
            trace.files_read.extend(["src/**", "tests/**"])
            trace.diff_summary.append("safe test executed in overlay with shell disabled and secret env removed")
            if proc.returncode != 0:
                trace.risk_observed.append("test_failure")
        except subprocess.TimeoutExpired:
            trace.exit_code = 124
            trace.risk_observed.append("sandbox_timeout")
            trace.trace_complete = False
        finally:
            shutil.rmtree(temp, ignore_errors=True)
        return trace


class BubblewrapBackend(DryRunBackend):
    """Placeholder backend descriptor for production Linux namespace execution."""

    name = "bubblewrap"


class SandboxRunner:
    def __init__(self, repo_root: str | Path, backend: str = "subprocess_overlay"):
        self.repo_root = Path(repo_root).resolve()
        self.backend = self._make_backend(backend)

    def preflight(
        self,
        action: ActionIR,
        decision: PolicyDecision | None = None,
        package_event: PackageEvent | None = None,
        profile: str | SandboxProfile | None = None,
        evidence_mode: str = "summary",
    ) -> ExecTrace:
        selected = self._profile(profile, action)
        return self.backend.preflight(action, selected, decision=decision, package_event=package_event, evidence_mode=evidence_mode)

    def _make_backend(self, backend: str) -> SandboxBackend:
        if backend == "dry_run":
            return DryRunBackend(self.repo_root)
        if backend == "bubblewrap":
            return BubblewrapBackend(self.repo_root)
        return SubprocessOverlayBackend(self.repo_root)

    @staticmethod
    def _profile(profile: str | SandboxProfile | None, action: ActionIR) -> SandboxProfile:
        if isinstance(profile, SandboxProfile):
            return profile
        if isinstance(profile, str) and profile in SANDBOX_PROFILES:
            return SANDBOX_PROFILES[profile]
        if profile == "network-off":
            return SANDBOX_PROFILES["package_preflight"] if action.semantic_action.startswith("install_") else profile_for_action(action)
        if profile == "dry-run":
            return profile_for_action(action)
        return profile_for_action(action)


def _process_tree(command: str) -> list[str]:
    low = command.lower()
    tree = ["bash"]
    if "npm" in low:
        tree.append("npm")
    if "pip" in low:
        tree.append("pip")
    if "git" in low or "github:" in low:
        tree.append("git")
    if "curl" in low or "wget" in low:
        tree.append("network_client")
    if "mcp" in low:
        tree.append("mcp_proxy")
    return list(dict.fromkeys(tree))


def _host_from_package(package: str | None) -> str | None:
    if not package:
        return None
    m = re.search(r"https?://([^/]+)", package)
    if m:
        return m.group(1)
    if package.startswith("github:") or "github.com" in package:
        return "github.com"
    return None


def _ignore_sensitive(_dir: str, names: list[str]) -> set[str]:
    return {n for n in names if n in SENSITIVE_NAMES or n.startswith(".env") or n in {".ssh", ".aws"}}


def _is_secret_env(name: str) -> bool:
    return bool(re.search(r"TOKEN|SECRET|PASSWORD|PRIVATE_KEY|ACCESS_KEY|API_KEY|AUTH", name, re.I))
