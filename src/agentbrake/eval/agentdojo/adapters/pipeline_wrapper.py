"""AgentDojo pipeline wrapper that inserts AgentBrake-Fusion before tool execution."""

from __future__ import annotations

from ast import literal_eval
from dataclasses import dataclass, field
from typing import Any, Callable

from agentdojo.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.basic_elements import InitQuery
from agentdojo.agent_pipeline.tool_execution import (
    EMPTY_FUNCTION_NAME,
    ToolsExecutionLoop,
    is_string_list,
    text_content_block_from_string,
    tool_result_to_str,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage

from ..state_tracker import AgentDojoStateTracker
from ..tool_gate import AgentBrakeToolGate

if False:  # pragma: no cover - typing only
    from ....control_plane import AgentBrakeControlPlane


@dataclass
class AgentBrakeAgentDojoContext:
    suite: str | None = None
    user_task_id: str | None = None
    injection_task_id: str | None = None
    task_instruction: str | None = None
    injection_instruction: str | None = None
    attack_goal: str | None = None
    attack_goal_signatures: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    source_has_untrusted: bool = False
    untrusted_observation_seen: bool = False
    private_data_seen: bool = False
    financial_data_seen: bool = False
    allowed_tools: list[str] = field(default_factory=list)
    allowed_tool_categories: list[str] = field(default_factory=list)
    run_id: str | None = None
    task_authorized_tool: bool | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "user_task_id": self.user_task_id,
            "injection_task_id": self.injection_task_id,
            "task_instruction": self.task_instruction,
            "injection_instruction": self.injection_instruction,
            "attack_goal": self.attack_goal,
            "attack_goal_signatures": list(self.attack_goal_signatures),
            "source_ids": list(self.source_ids),
            "source_has_untrusted": self.source_has_untrusted,
            "untrusted_observation_seen": self.untrusted_observation_seen,
            "private_data_seen": self.private_data_seen,
            "financial_data_seen": self.financial_data_seen,
            "allowed_tools": list(self.allowed_tools),
            "allowed_tool_categories": list(self.allowed_tool_categories),
            "run_id": self.run_id,
            "task_authorized_tool": self.task_authorized_tool,
            **self.metadata,
        }


class AgentBrakeToolExecutor(BasePipelineElement):
    def __init__(
        self,
        tool_gate: AgentBrakeToolGate,
        context_getter: Callable[[], AgentBrakeAgentDojoContext],
        tool_output_formatter: Callable[[Any], str] = tool_result_to_str,
    ) -> None:
        self.tool_gate = tool_gate
        self.context_getter = context_getter
        self.output_formatter = tool_output_formatter

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: list[ChatMessage] | tuple[ChatMessage, ...] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, list[ChatMessage] | tuple[ChatMessage, ...], dict]:
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        if messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        context = self.context_getter().as_dict()
        tool_call_results = []
        for tool_call in messages[-1]["tool_calls"]:
            tool_name = getattr(tool_call, "function", None) or getattr(tool_call, "name", None) or ""
            tool_args = getattr(tool_call, "args", None) or getattr(tool_call, "arguments", None) or {}
            if tool_name == EMPTY_FUNCTION_NAME:
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error="Empty function name provided. Provide a valid function name.",
                    )
                )
                continue
            if not isinstance(tool_args, dict):
                tool_args = {"value": tool_args}
            for arg_k, arg_v in list(tool_args.items()):
                if isinstance(arg_v, str) and is_string_list(arg_v):
                    tool_args[arg_k] = literal_eval(arg_v)

            gate_result = self.tool_gate.guard_tool_call(
                tool_call,
                {
                    **context,
                    "tool_args": tool_args,
                    "run_preflight": bool(context.get("run_preflight", True)),
                },
            )
            action = gate_result.action
            tool_info = action.metadata.get("agentdojo", {}) if action else {}

            if gate_result.execute:
                tool_result, error = runtime.run_function(env, tool_name, tool_args)
                if not context.get("disable_state_tracker"):
                    self.tool_gate.state_tracker.observe_tool_result(
                        tool_name,
                        tool_result,
                        suite=context.get("suite"),
                        tool_category=str(tool_info.get("tool_category") or ""),
                        semantic_action=str(tool_info.get("semantic_action") or ""),
                        registered=bool(tool_info.get("registered", True)),
                        side_effect=bool(tool_info.get("side_effect")),
                    )
                    tool_result = self.tool_gate.state_tracker.sanitize_tool_result(
                        tool_name,
                        tool_result,
                        suite=context.get("suite"),
                        tool_category=str(tool_info.get("tool_category") or ""),
                        semantic_action=str(tool_info.get("semantic_action") or ""),
                        registered=bool(tool_info.get("registered", True)),
                        side_effect=bool(tool_info.get("side_effect")),
                    )
            else:
                tool_result = gate_result.safe_tool_result
                error = gate_result.safe_tool_result.get("error")
                if not context.get("disable_state_tracker"):
                    self.tool_gate.state_tracker.observe_tool_result(
                        tool_name,
                        tool_result,
                        suite=context.get("suite"),
                        tool_category=str(tool_info.get("tool_category") or "unknown_side_effect"),
                        semantic_action=str(tool_info.get("semantic_action") or "unknown_side_effect"),
                        registered=bool(tool_info.get("registered", False)),
                        side_effect=bool(tool_info.get("side_effect", True)),
                    )

            formatted_tool_call_result = self.output_formatter(tool_result)
            tool_call_results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(formatted_tool_call_result)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
        return query, runtime, env, [*messages, *tool_call_results], extra_args


class AgentBrakeAgentDojoPipeline(BasePipelineElement):
    """Pipeline wrapper that keeps the AgentDojo execution loop intact."""

    def __init__(
        self,
        llm: BasePipelineElement,
        control_plane: "AgentBrakeControlPlane",
        *,
        system_message: str | None = None,
        tool_output_formatter: Callable[[Any], str] = tool_result_to_str,
        max_iters: int = 15,
    ) -> None:
        llm_name = str(getattr(llm, "name", getattr(llm, "model", "local")))
        self.name = f"{llm_name}-agentbrake_toolgate"
        self.control_plane = control_plane
        self.state_tracker = AgentDojoStateTracker()
        self.context = AgentBrakeAgentDojoContext()
        self.tool_gate = AgentBrakeToolGate(control_plane)
        self.tool_gate.state_tracker = self.state_tracker
        self._executor = AgentBrakeToolExecutor(self.tool_gate, lambda: self.context, tool_output_formatter=tool_output_formatter)
        self._pipeline = AgentPipeline(elements=[InitQuery(), llm, ToolsExecutionLoop([self._executor, llm], max_iters=max_iters)])
        self._pipeline.name = self.name
        self._max_iters = max_iters
        self.system_message = system_message

    def set_context(self, context: AgentBrakeAgentDojoContext | dict[str, Any]) -> None:
        if isinstance(context, AgentBrakeAgentDojoContext):
            self.context = context
        else:
            self.context = AgentBrakeAgentDojoContext(**context)
        self.tool_gate.state_tracker = self.state_tracker

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: list[ChatMessage] | tuple[ChatMessage, ...] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, list[ChatMessage] | tuple[ChatMessage, ...], dict]:
        extra_args = dict(extra_args or {})
        extra_args["agentbrake_agentdojo_context"] = self.context.as_dict()
        extra_args["agentbrake_toolgate"] = True
        return self._pipeline.query(query, runtime, env, messages, extra_args)


def build_agentbrake_agentdojo_pipeline(
    llm: BasePipelineElement,
    control_plane: "AgentBrakeControlPlane",
    *,
    system_message: str | None = None,
    tool_output_formatter: Callable[[Any], str] = tool_result_to_str,
    max_iters: int = 15,
) -> AgentBrakeAgentDojoPipeline:
    return AgentBrakeAgentDojoPipeline(
        llm,
        control_plane,
        system_message=system_message,
        tool_output_formatter=tool_output_formatter,
        max_iters=max_iters,
    )


