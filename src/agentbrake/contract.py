"""Task contract generation and intent-boundary checks."""

from __future__ import annotations

import fnmatch
from pathlib import PurePosixPath

from .models import ActionIR, IntentDiff, TaskContract, new_id


class TaskContractBuilder:
    """Heuristic task-contract builder for the reference agent.

    A production adapter can replace this with an LLM-assisted contract builder,
    but the contract object and fail-closed matching stay the same.
    """

    def build(self, user_prompt: str) -> TaskContract:
        p = user_prompt.lower()
        allowed_files = ["src/**", "tests/**"]
        allowed_actions = ["read_project_file", "edit_source_file", "run_tests", "run_lint"]
        conditional: list[dict[str, str]] = [
            {"action": "install_registry_dependency", "condition": "approved registry + human approval + no lifecycle"}
        ]
        forbidden = [
            "read_secret_file",
            "send_network_request",
            "modify_ci_pipeline",
            "publish_artifact",
            "git_push_force",
            "invoke_deploy_tool",
            "modify_registry_config",
        ]
        confidence = 0.78
        goal = "general_code_task"
        allowed_network: list[str] = []
        allowed_commands = ["git status", "git diff", "pytest", "python -m pytest", "npm test"]
        allowed_tools = ["Read", "Edit", "Bash"]
        allowed_recipients: list[str] = []
        allowed_package_sources = ["registry"]

        if any(word in p for word in ["登录", "login", "按钮", "button"]):
            goal = "fix_login_button_click_bug"
            allowed_files = ["src/**", "tests/**", "package.json"]
            confidence = 0.87
        elif any(word in p for word in ["安装", "install", "依赖", "dependency", "eslint"]):
            goal = "configure_dependency_or_tooling"
            allowed_files = ["src/**", "tests/**", "package.json", "package-lock.json", "pyproject.toml", "requirements.txt"]
            allowed_actions.append("install_registry_dependency")
            allowed_network = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]
            confidence = 0.75
        elif any(word in p for word in ["发布", "release", "publish"]):
            goal = "release_artifact"
            allowed_files = ["src/**", "tests/**", "package.json", ".github/workflows/**", "scripts/**"]
            conditional.append({"action": "publish_artifact", "condition": "double approval + dry-run first + exact hash binding"})
            confidence = 0.65

        return TaskContract(
            task_id=new_id("task"),
            goal=goal,
            user_prompt=user_prompt,
            allowed_files=allowed_files,
            forbidden_files=[".env", ".env.*", "~/.ssh/**", "~/.aws/**", ".npmrc", ".pypirc", "secrets/**"],
            allowed_actions=allowed_actions,
            conditionally_allowed_actions=conditional,
            forbidden_actions=forbidden,
            allowed_network=allowed_network,
            allowed_commands=allowed_commands,
            allowed_tools=allowed_tools,
            allowed_recipients=allowed_recipients,
            allowed_package_sources=allowed_package_sources,
            confirmation_required=confidence < 0.7,
            confirmation_summary=f"{goal}: files={','.join(allowed_files)} actions={','.join(allowed_actions)}",
            confidence=confidence,
        )


class IntentMatcher:
    def match(self, contract: TaskContract, action: ActionIR) -> IntentDiff:
        reasons: list[str] = []
        semantic = action.semantic_action

        if semantic in contract.forbidden_actions:
            reasons.append("forbidden_by_task_contract")
            return IntentDiff(action.action_id, semantic, "violation", reasons, "block_or_approval")

        if semantic in contract.allowed_actions:
            if self._files_allowed(contract, action):
                return IntentDiff(action.action_id, semantic, "match", [], "allow")
            reasons.append("affected_file_outside_allowed_scope")
            return IntentDiff(action.action_id, semantic, "partial_match", reasons, "sandbox_or_approval")

        conditional_names = {item.get("action") for item in contract.conditionally_allowed_actions}
        if semantic in conditional_names or semantic.startswith("install_"):
            reasons.append("conditional_action_requires_approval")
            if not self._files_allowed(contract, action):
                reasons.append("affected_file_outside_allowed_scope")
            return IntentDiff(action.action_id, semantic, "partial_match", reasons, "approval")

        if semantic == "unknown_side_effect":
            reasons.append("unknown_action_semantics")
            return IntentDiff(action.action_id, semantic, "unknown", reasons, "sandbox_then_approval")

        reasons.append("not_required_by_user_goal")
        return IntentDiff(action.action_id, semantic, "violation", reasons, "block_or_approval")

    def _files_allowed(self, contract: TaskContract, action: ActionIR) -> bool:
        paths = [p for p in action.affected_assets if p and not p.startswith("env:")]
        if not paths:
            return True
        for p in paths:
            norm = self._norm(p)
            if any(fnmatch.fnmatch(norm, self._norm(glob)) for glob in contract.forbidden_files):
                return False
            if not any(fnmatch.fnmatch(norm, self._norm(glob)) for glob in contract.allowed_files):
                return False
        return True

    @staticmethod
    def _norm(path: str) -> str:
        return str(PurePosixPath(path.replace("\\", "/"))).lstrip("/")
