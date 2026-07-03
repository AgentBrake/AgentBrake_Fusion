"""Convert raw agent tool calls to ActionIR."""

from __future__ import annotations

import base64
import re
import shlex
from pathlib import Path

from .action_graph import ensure_action_graph
from .models import ActionIR, Risk, new_id

NETWORK_CMD_RE = re.compile(
    r"\b(curl|wget|httpie|nc|netcat|nslookup|dig|ssh|scp|ftp|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer)\b", re.I
)
PY_NODE_EGRESS_RE = re.compile(r"\b(python|python3|node)\b.*\b(requests|urllib|fetch|http\.|https\.|net\.|socket)\b", re.I | re.S)
SECRET_PATH_RE = re.compile(
    r"(^|[\s'\"`|<>=:])(~?/)?(\.env(\.[\w.-]+)?|secrets/|\.ssh/|id_rsa|id_ed25519|\.npmrc|\.pypirc)([\s'\"`|;]|$)", re.I
)
PUBLISH_RE = re.compile(r"\b(npm\s+publish|twine\s+upload|docker\s+push|gh\s+release\s+create)\b", re.I)
FORCE_PUSH_RE = re.compile(r"\bgit\s+push\b.*(--force|-f|\+)", re.I)
TEST_RE = re.compile(r"\b(npm\s+(run\s+)?test|pnpm\s+test|yarn\s+test|pytest|python\s+-m\s+pytest|go\s+test|cargo\s+test)\b", re.I)
INSTALL_RE = re.compile(r"\b(npm|pnpm|yarn|pip|pip3|poetry|cargo|go)\s+(install|i|add|get)\b", re.I)
REGISTRY_CONFIG_RE = re.compile(r"\b(npm\s+config\s+set\s+registry|pip\s+config\s+set|\.npmrc|\.pypirc)\b", re.I)
CI_PATH_RE = re.compile(r"\.github/workflows/.*\.(yml|yaml)$", re.I)
COMPOUND_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")
SHELL_WRAPPER_RE = re.compile(
    r"^\s*(?:bash|sh|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)\s+(?:-Command|-c|/c)\s+(.+)$", re.I | re.S
)
POWERSHELL_ENCODED_RE = re.compile(r"\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b.*(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]+)", re.I)
DESTRUCTIVE_FILE_RE = re.compile(
    r"(?:\brm\s+-rf\b|\bRemove-Item\b.*-Recurse\b|\bdel\s+/[sq]\b|\brmdir\s+/[sq]\b|\bchmod\s+777\b|\bchown\s+-R\b)", re.I | re.S
)


class ActionParser:
    def parse(
        self,
        raw_action: str,
        tool: str = "Bash",
        cwd: str | Path = ".",
        source_ids: list[str] | None = None,
        file_path: str | None = None,
        operation: str | None = None,
        _depth: int = 0,
    ) -> ActionIR:
        source_ids = source_ids or []
        tool_norm = tool.lower()
        action_id = new_id("act")
        raw = raw_action.strip()
        cwd_s = str(cwd)
        command_parts = self._split_compound(raw)

        if _depth < 2:
            decoded = self._decode_powershell_encoded(raw)
            if decoded:
                action = self.parse(
                    decoded, tool=tool, cwd=cwd, source_ids=source_ids, file_path=file_path, operation=operation, _depth=_depth + 1
                )
                action.raw_action = raw
                action.risk_tags = list(dict.fromkeys([*action.risk_tags, "encoded_command", "obfuscated_shell"]))
                action.metadata.update({"decoded_action": decoded, "wrapper": "powershell_encoded"})
                return action

            wrapped = self._extract_shell_wrapper(raw)
            if wrapped:
                action = self.parse(
                    wrapped, tool=tool, cwd=cwd, source_ids=source_ids, file_path=file_path, operation=operation, _depth=_depth + 1
                )
                action.raw_action = raw
                action.risk_tags = list(dict.fromkeys([*action.risk_tags, "shell_wrapper"]))
                action.metadata.update({"inner_action": wrapped, "wrapper": "shell"})
                return action

            if len(command_parts) > 1:
                return self._aggregate_compound(raw, tool, cwd, source_ids, command_parts, _depth)

        if tool_norm == "mcp":
            capability = (
                "deploy"
                if re.search(r"deploy|publish|delete|remove|destroy", raw, re.I)
                else "write"
                if re.search(r"create|update|write", raw, re.I)
                else "read"
            )
            return self.parse_mcp_call("mcp_adapter", raw, capability, {"raw_action": raw}, source_ids=source_ids)

        if operation or tool_norm in {"read", "write", "edit", "delete"}:
            path = file_path or raw
            semantic, risk, side_effect, tags, requires, affected, metadata = self._parse_file_op(operation or tool_norm, path, cwd)
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                semantic,
                risk,
                tags,
                affected,
                requires,
                source_ids,
                0.95,
                side_effect,
                command_parts,
                metadata=metadata,
            )

        if re.search(r"\.github/workflows/", raw, re.I) and re.search(r">|tee|sed\s+-i|python|node|cat|echo", raw, re.I):
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                "modify_ci_pipeline",
                "high",
                ["ci_cd", "workflow_write"],
                [".github/workflows/**"],
                ["human_approval", "ci_dry_run"],
                source_ids,
                0.88,
                True,
                command_parts,
            )

        if SECRET_PATH_RE.search(raw) and re.search(
            r"\b(cat|less|more|grep|sed|awk|printenv|env|python|node|Get-Content|gc|type)\b", raw, re.I
        ):
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                "read_secret_file",
                "critical",
                ["secret_access", "credential_exposure"],
                self._extract_secret_paths(raw),
                ["block"],
                source_ids,
                0.97,
                False,
                command_parts,
            )

        if PUBLISH_RE.search(raw):
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                "publish_artifact",
                "critical",
                ["supply_chain", "publish", "external_write"],
                ["registry", "package"],
                ["double_approval", "dry_run"],
                source_ids,
                0.95,
                True,
                command_parts,
            )

        if FORCE_PUSH_RE.search(raw):
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                "git_push_force",
                "critical",
                ["git_remote", "destructive_write"],
                ["git_remote"],
                ["block_or_double_approval"],
                source_ids,
                0.92,
                True,
                command_parts,
            )

        if REGISTRY_CONFIG_RE.search(raw):
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                "modify_registry_config",
                "critical",
                ["supply_chain", "registry_config"],
                [".npmrc", ".pypirc"],
                ["human_approval"],
                source_ids,
                0.9,
                True,
                command_parts,
            )

        if INSTALL_RE.search(raw):
            semantic, tags, affected, risk, package_args = self._parse_install(raw)
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                semantic,
                risk,
                tags,
                affected,
                ["sandbox_preflight", "human_approval"],
                source_ids,
                0.93,
                True,
                command_parts,
                metadata={"package_args": package_args},
            )

        if NETWORK_CMD_RE.search(raw) or PY_NODE_EGRESS_RE.search(raw):
            host = self._extract_host(raw) or "unknown"
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                "send_network_request",
                "high",
                ["network_egress"],
                [host],
                ["network_policy", "secret_taint_check"],
                source_ids,
                0.87,
                True,
                command_parts,
            )

        if TEST_RE.search(raw):
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                "run_tests",
                "medium",
                ["test_runner"],
                ["src/**", "tests/**"],
                ["sandbox"],
                source_ids,
                0.9,
                True,
                command_parts,
            )

        if raw.startswith(("ls", "pwd", "git status", "git diff")):
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                "read_project_file",
                "low",
                ["read_only"],
                self._extract_paths(raw),
                [],
                source_ids,
                0.8,
                False,
                command_parts,
            )

        if DESTRUCTIVE_FILE_RE.search(raw):
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                "unknown_side_effect",
                "critical",
                ["destructive_file_operation", "parser_uncertain"],
                self._extract_paths(raw),
                ["sandbox_then_approval"],
                source_ids,
                0.72,
                True,
                command_parts,
            )

        side_effect = bool(
            re.search(
                r"\b(rm|mv|cp|chmod|chown|touch|echo|python|node|bash|sh|make|docker|gh|powershell|pwsh|cmd|Remove-Item|del|rmdir)\b|>|>>",
                raw,
                re.I,
            )
        )
        if not side_effect:
            return ActionIR(
                action_id,
                raw,
                tool,
                cwd_s,
                "read_project_file",
                "low",
                ["read_or_inspect"],
                self._extract_paths(raw),
                [],
                source_ids,
                0.65,
                False,
                command_parts,
            )

        return ActionIR(
            action_id,
            raw,
            tool,
            cwd_s,
            "unknown_side_effect",
            "high",
            ["parser_uncertain"],
            [],
            ["sandbox_then_approval"],
            source_ids,
            0.45,
            True,
            command_parts,
        )

    def parse_mcp_call(self, server_id: str, tool_name: str, capability: str, args: dict, source_ids: list[str] | None = None) -> ActionIR:
        risk: Risk = (
            "critical"
            if capability in {"deploy", "publish", "delete", "auth"}
            else "high"
            if capability in {"write", "external_write"}
            else "medium"
        )
        semantic = "invoke_destructive_mcp_tool" if risk == "critical" else "invoke_mcp_tool"
        return ActionIR(
            new_id("act"),
            f"MCP {server_id}.{tool_name}({args})",
            "MCP",
            ".",
            semantic,
            risk,
            ["mcp_tool", f"capability:{capability}"],
            [f"mcp:{server_id}:{tool_name}"],
            ["mcp_proxy", "human_approval"] if risk != "medium" else ["mcp_proxy"],
            source_ids or [],
            0.95,
            capability not in {"read"},
            metadata={"mcp_args": args},
        )

    def _parse_file_op(
        self, op: str, path: str, cwd: str | Path = "."
    ) -> tuple[str, Risk, bool, list[str], list[str], list[str], dict[str, str]]:
        op = op.lower()
        norm = path.replace("\\", "/")
        repo = Path(cwd).resolve()
        resolved = (repo / path).resolve(strict=False) if not Path(path).is_absolute() else Path(path).resolve(strict=False)
        metadata = {"canonical_path": str(resolved)}
        try:
            rel = resolved.relative_to(repo).as_posix()
        except ValueError:
            return "unknown_side_effect", "critical", True, ["path_escape_repo_root"], ["block"], [norm], metadata

        path_obj = repo / rel
        if path_obj.is_symlink():
            target = path_obj.resolve(strict=False)
            metadata["symlink_target"] = str(target)
            try:
                target.relative_to(repo)
            except ValueError:
                return "unknown_side_effect", "critical", True, ["symlink_escape_repo_root"], ["block"], [rel], metadata

        canonical_norm = rel.replace("\\", "/")
        basename = Path(canonical_norm).name.lower()
        hidden_sensitive = canonical_norm.startswith(".") and basename in {".env", ".npmrc", ".pypirc"}
        if SECRET_PATH_RE.search(norm) or SECRET_PATH_RE.search(canonical_norm) or hidden_sensitive:
            return "read_secret_file", "critical", False, ["secret_access"], ["block"], [canonical_norm], metadata
        if CI_PATH_RE.search(canonical_norm):
            if op in {"write", "edit", "delete"}:
                return "modify_ci_pipeline", "high", True, ["ci_cd"], ["human_approval", "ci_dry_run"], [canonical_norm], metadata
            return "read_project_file", "low", False, ["ci_cd", "file_read"], [], [canonical_norm], metadata
        if op in {"write", "edit"}:
            return "edit_source_file", "medium", True, ["file_write"], ["record_diff"], [canonical_norm], metadata
        if op == "delete":
            return "unknown_side_effect", "high", True, ["delete_file"], ["sandbox_then_approval"], [canonical_norm], metadata
        return "read_project_file", "low", False, ["file_read"], [], [canonical_norm], metadata

    def _aggregate_compound(
        self, raw: str, tool: str, cwd: str | Path, source_ids: list[str], command_parts: list[str], _depth: int
    ) -> ActionIR:
        children = [self.parse(part, tool=tool, cwd=cwd, source_ids=source_ids, _depth=_depth + 1) for part in command_parts]
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        worst = max(children, key=lambda a: risk_order[a.risk])
        dangerous = [
            child
            for child in children
            if child.semantic_action not in {"read_project_file", "run_tests"} or child.risk in {"high", "critical"}
        ]
        semantic = (
            worst.semantic_action
            if dangerous
            else "run_tests"
            if any(c.semantic_action == "run_tests" for c in children)
            else worst.semantic_action
        )
        risk: Risk = worst.risk
        side_effect = any(c.side_effect for c in children)
        tags: list[str] = ["compound_command"]
        affected: list[str] = []
        requires: list[str] = []
        for child in children:
            tags.extend(child.risk_tags)
            affected.extend(child.affected_assets)
            requires.extend(child.requires)
        if dangerous:
            tags.append("compound_contains_dangerous_part")
            requires.append("sandbox_then_approval")
        action = ActionIR(
            new_id("act"),
            raw,
            tool,
            str(cwd),
            semantic,
            risk,
            list(dict.fromkeys(tags)),
            list(dict.fromkeys(affected)),
            list(dict.fromkeys(requires)),
            source_ids,
            min(c.parser_confidence for c in children),
            side_effect,
            command_parts,
            metadata={"compound_children": [c.semantic_action for c in children]},
        )
        ensure_action_graph(action, run_id="parser")
        return action

    def _parse_install(self, raw: str) -> tuple[str, list[str], list[str], Risk, list[str]]:
        targets = self._install_targets(raw)
        tags = ["package_manager", "supply_chain"]
        affected = ["package.json", "package-lock.json", "node_modules"]
        semantic = "install_registry_dependency"
        risk: Risk = "high"
        if any(re.search(r"(^git\+|github:|git@|https?://|\.tgz$|\.tar\.gz$)", t, re.I) for t in targets):
            semantic = (
                "install_git_dependency"
                if any("github:" in t or t.startswith(("git+", "git@")) for t in targets)
                else "install_tarball_dependency"
            )
            tags.extend(["external_code", "git_or_url_dependency", "package_lifecycle_script_possible"])
            risk = (
                "critical" if any("attacker" in t.lower() or "unknown" in t.lower() or "helper" in t.lower() for t in targets) else "high"
            )
        else:
            tags.extend(["registry_dependency", "package_lifecycle_script_possible"])
        if re.search(r"\b(pip|pip3|poetry)\b", raw, re.I):
            affected = ["pyproject.toml", "requirements.txt", "site-packages"]
            tags.append("python_package")
        return semantic, tags, affected, risk, targets

    def _install_targets(self, raw: str) -> list[str]:
        try:
            tokens = shlex.split(raw)
        except ValueError:
            tokens = raw.split()
        targets: list[str] = []
        skip_next = False
        for token in tokens:
            if skip_next:
                skip_next = False
                continue
            low = token.lower()
            if low in {"npm", "pnpm", "yarn", "pip", "pip3", "poetry", "cargo", "go", "install", "i", "add", "get"}:
                continue
            if low.startswith("-"):
                if low in {"-r", "--requirement", "--registry", "--index-url", "-i"}:
                    skip_next = True
                continue
            if re.match(r"[\w@./:+\-]+", token):
                targets.append(token)
        return targets

    @staticmethod
    def _split_compound(raw: str) -> list[str]:
        return [p.strip() for p in COMPOUND_SPLIT_RE.split(raw) if p.strip()]

    @staticmethod
    def _extract_secret_paths(raw: str) -> list[str]:
        found = []
        for m in re.finditer(
            r"(~?/)?(\.env(?:\.[\w.-]+)?|secrets/[^\s'\"`|;]*|\.ssh/[^\s'\"`|;]*|id_rsa|id_ed25519|\.npmrc|\.pypirc)", raw, re.I
        ):
            found.append(m.group(0))
        return found or ["secret"]

    @staticmethod
    def _extract_paths(raw: str) -> list[str]:
        try:
            tokens = shlex.split(raw)
        except ValueError:
            tokens = raw.split()
        paths = [t for t in tokens[1:] if not t.startswith("-") and "://" not in t]
        return paths[:8]

    @staticmethod
    def _extract_host(raw: str) -> str | None:
        m = re.search(r"https?://([^/\s'\"]+)", raw, re.I)
        if m:
            return m.group(1)
        m = re.search(r"\b(?:curl|wget|nc|netcat|ssh|scp|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\s+([^\s'\"]+)", raw, re.I)
        return m.group(1) if m else None

    @staticmethod
    def _extract_shell_wrapper(raw: str) -> str | None:
        m = SHELL_WRAPPER_RE.search(raw)
        if not m:
            return None
        inner = m.group(1).strip()
        try:
            parts = shlex.split(inner)
            if len(parts) == 1:
                inner = parts[0]
        except ValueError:
            inner = inner.strip("'\"")
        return inner.strip("'\"") or None

    @staticmethod
    def _decode_powershell_encoded(raw: str) -> str | None:
        m = POWERSHELL_ENCODED_RE.search(raw)
        if not m:
            return None
        token = m.group(1)
        try:
            data = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
        except Exception:
            return None
        for encoding in ("utf-16le", "utf-8"):
            try:
                decoded = data.decode(encoding).strip("\x00 \r\n\t")
            except UnicodeDecodeError:
                continue
            if decoded:
                return decoded
        return None
