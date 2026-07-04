"""Run Agent-SafetyBench with Progent-style least-privilege tool gating.

This runner keeps the official Agent-SafetyBench environment and output format,
but inserts Progent before each environment tool execution:

    user task + tools -> Progent policy -> model candidate tool call -> policy check -> env.call_tool(...)

The generated ``gen_res.json`` can be scored by the official ShieldAgent script.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from pathlib import Path
from typing import Any

from jsonschema import validate
from openai import OpenAI

from agentbrake_runner import (
    DEFAULT_DATA,
    DEFAULT_UPSTREAM,
    OpenAICompatibleAgent,
    _add_upstream_paths,
    _build_agent,
    _call_env_tool_safely,
    _load_cases,
    _load_dotenv,
    _ordered_results,
    _preview,
    _provider_safe_dialog,
    _write_json,
    parse_envs,
)


DEFAULT_OUT = Path("experiments/agent_safetybench/reports/progent_rerun")
DEFAULT_PROGENT = Path(__file__).resolve().parent / "baselines" / "Progent"


class ProgentPolicyError(Exception):
    """Raised when a tool call violates the generated Progent policy."""


class ProgentPolicyEngine:
    """Stateless Progent policy generator/checker for concurrent ASB runs."""

    def __init__(
        self,
        *,
        progent_dir: Path,
        model: str,
        api_key: str,
        base_url: str,
        timeout: float,
        max_tokens: int,
    ) -> None:
        self.model = model
        self.client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)
        self.max_tokens = max_tokens
        self.system_prompt = _load_progent_asb_prompt(progent_dir)

    def generate_policy(self, *, user_query: str, tools: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
        content = "TOOLS: " + json.dumps(tools, ensure_ascii=False) + "\nUSER_QUERY: " + user_query
        temperature = 0.0
        last_error: Exception | None = None
        for attempt in range(6):
            try:
                text = self._chat(self.system_prompt, content, temperature=temperature)
                policy = _extract_progent_json(text)
                if policy is None:
                    return [], text
                if not isinstance(policy, list):
                    raise ValueError(f"Progent policy is not a list: {type(policy).__name__}")
                normalized = []
                for item in policy:
                    if not isinstance(item, dict) or not item.get("name"):
                        continue
                    args = item.get("args") if isinstance(item.get("args"), dict) else {}
                    normalized.append({"name": str(item["name"]), "args": args})
                return normalized, text
            except Exception as exc:  # noqa: BLE001 - provider/parser exceptions vary.
                last_error = exc
                temperature += 0.2
                time.sleep(min(6.0, 0.6 * (2**attempt)) + random.random())
        raise RuntimeError(f"Progent policy generation failed: {last_error}") from last_error

    def _chat(self, system_prompt: str, user_prompt: str, *, temperature: float) -> str:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": self.max_tokens,
            "seed": 0,
            "extra_body": {"enable_thinking": False},
        }
        try:
            completion = self.client.chat.completions.create(**kwargs)
        except Exception as exc:
            if "extra_body" in str(exc) or "enable_thinking" in str(exc):
                kwargs.pop("extra_body", None)
                completion = self.client.chat.completions.create(**kwargs)
            else:
                raise
        return completion.choices[0].message.content or ""

    def check_tool_call(self, *, policy: list[dict[str, Any]], tool_name: str, arguments: dict[str, Any]) -> None:
        matching = [item for item in policy if item.get("name") == tool_name]
        if not matching:
            raise ProgentPolicyError(f"The tool '{tool_name}' is not allowed by the generated Progent policy.")
        errors: list[str] = []
        for item in matching:
            restrictions = item.get("args") if isinstance(item.get("args"), dict) else {}
            try:
                for arg_name, restriction in restrictions.items():
                    if arg_name in arguments:
                        _check_arg(arg_name, arguments[arg_name], restriction)
                return
            except Exception as exc:  # noqa: BLE001 - mirrors Progent's permissive schema checking style.
                errors.append(str(exc))
        detail = "; ".join(errors) if errors else "arguments did not match any generated restriction"
        raise ProgentPolicyError(f"The tool '{tool_name}' arguments violate the generated Progent policy: {detail}")


def run(args: argparse.Namespace) -> dict[str, Any]:
    _load_dotenv(Path(args.env_file) if args.env_file else Path(".env"))
    upstream_dir = Path(args.upstream_dir).resolve()
    data_path = Path(args.data).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    _add_upstream_paths(upstream_dir)
    from EnvManager import EnvManager  # type: ignore[import-not-found]

    data = _load_cases(data_path, args.limit, args.case_ids, args.risk_contains)
    gen_res: list[dict[str, Any]] = []
    if args.resume and (out_dir / "gen_res.json").exists():
        try:
            loaded = json.loads((out_dir / "gen_res.json").read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                gen_res = [item for item in loaded if isinstance(item, dict)]
        except Exception:
            gen_res = []

    existing_by_id = {str(item.get("id")): item for item in gen_res}
    result_by_index = {
        index: existing_by_id[str(case.get("id"))]
        for index, case in enumerate(data)
        if str(case.get("id")) in existing_by_id
    }
    pending = [(index, case) for index, case in enumerate(data) if str(case.get("id")) not in existing_by_id]
    errors: list[dict[str, Any]] = []
    trace_path = out_dir / "progent_trace.jsonl"
    if trace_path.exists() and not args.resume:
        trace_path.unlink()

    started = time.perf_counter()
    if args.workers <= 1:
        api = _build_agent(_agent_args_for_model(args))
        policy_engine = _build_policy_engine(args)
        env_manager = EnvManager()
        for index, case in pending:
            try:
                result = evaluate_case(
                    case=case,
                    api=api,
                    policy_engine=policy_engine,
                    env_manager=env_manager,
                    max_rounds=args.max_rounds,
                    fail_open=args.policy_fail_open,
                )
                result_by_index[index] = result
                _append_traces(trace_path, result.get("progent_tool_traces", []))
                _write_json(out_dir / "gen_res.json", _ordered_results(data, result_by_index))
                print(_progress_line(len(result_by_index), len(data), case, result), flush=True)
            except Exception as exc:  # noqa: BLE001
                errors.append({"id": case.get("id"), "error": str(exc)})
                _write_json(out_dir / "errors.json", errors)
                print(f"[error] id={case.get('id')}: {exc}", flush=True)
                if args.fail_fast:
                    raise
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(_evaluate_case_worker, case=case, args=args): (index, case)
                for index, case in pending
            }
            for future in as_completed(futures):
                index, case = futures[future]
                try:
                    result = future.result()
                    result_by_index[index] = result
                    _append_traces(trace_path, result.get("progent_tool_traces", []))
                    _write_json(out_dir / "gen_res.json", _ordered_results(data, result_by_index))
                    print(_progress_line(len(result_by_index), len(data), case, result), flush=True)
                except Exception as exc:  # noqa: BLE001
                    errors.append({"id": case.get("id"), "error": str(exc)})
                    _write_json(out_dir / "errors.json", errors)
                    print(f"[error] id={case.get('id')}: {exc}", flush=True)
                    if args.fail_fast:
                        raise

    gen_res = _ordered_results(data, result_by_index)
    summary = summarize_progent_run(gen_res, errors, started, args)
    _write_json(out_dir / "gen_res.json", gen_res)
    _write_json(out_dir / "errors.json", errors)
    _write_json(out_dir / "summary.json", summary)
    (out_dir / "summary.md").write_text(render_summary(summary), encoding="utf-8")
    return summary


def evaluate_case(
    *,
    case: dict[str, Any],
    api: OpenAICompatibleAgent,
    policy_engine: ProgentPolicyEngine,
    env_manager: Any,
    max_rounds: int,
    fail_open: bool,
) -> dict[str, Any]:
    envs, tool_descs, tool_env_map = parse_envs(case.get("environments") or [], env_manager)
    tools = [{"type": "function", "function": deepcopy(item)} for item in tool_descs]
    progent_tools = _to_progent_tools(tool_descs)
    user_query = _case_user_query(case)
    policy_error = ""
    raw_policy_text = ""
    try:
        policy, raw_policy_text = policy_engine.generate_policy(user_query=user_query, tools=progent_tools)
    except Exception as exc:  # noqa: BLE001
        policy = []
        policy_error = str(exc)

    messages = [{"role": "system", "content": api.system_prompt()}]
    if "dialog" in case:
        messages.extend(_provider_safe_dialog(case["dialog"]))
    else:
        messages.append({"role": "user", "content": str(case.get("instruction", ""))})

    traces: list[dict[str, Any]] = []
    final_result: list[dict[str, Any]] | None = None
    rounds = 0
    while rounds < max_rounds:
        completion = api.generate_response(messages, tools)
        rounds += 1
        if completion is None:
            continue
        if completion.get("type") == "tool":
            tool_name = str(completion.get("tool_name", "unknown_tool"))
            arguments = dict(completion.get("arguments") or {})
            tool_call_id = str(completion.get("tool_call_id") or f"call_{case.get('id')}_{rounds}")
            tool_call_result, trace = progent_call_tool(
                case=case,
                envs=envs,
                tool_env_map=tool_env_map,
                policy_engine=policy_engine,
                policy=policy,
                policy_error=policy_error,
                tool_name=tool_name,
                arguments=arguments,
                tool_call_id=tool_call_id,
                round_index=rounds,
                fail_open=fail_open,
            )
            traces.append(trace)
            assistant_tool_message = completion.get("assistant_message")
            if not isinstance(assistant_tool_message, dict):
                assistant_tool_message = {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": tool_call_id,
                            "type": "function",
                            "function": {
                                "arguments": json.dumps(arguments, ensure_ascii=False),
                                "name": tool_name,
                            },
                        }
                    ],
                }
            messages.append(assistant_tool_message)
            messages.append(
                {
                    "role": "tool",
                    "content": json.dumps(tool_call_result, ensure_ascii=False, default=str),
                    "tool_call_id": tool_call_id,
                    "name": tool_name,
                }
            )
            continue

        assistant_message = completion.get("assistant_message")
        content = str(completion.get("content", ""))
        messages.append(assistant_message if isinstance(assistant_message, dict) else {"role": "assistant", "content": content})
        final_result = messages
        break

    if final_result is None:
        final_result = messages

    out = deepcopy(case)
    out["output"] = final_result
    out["rounds"] = rounds
    out["progent_policy"] = policy
    out["progent_policy_error"] = policy_error
    out["progent_policy_raw_preview"] = _preview(raw_policy_text, 800)
    out["progent_tool_traces"] = traces
    return out


def progent_call_tool(
    *,
    case: dict[str, Any],
    envs: list[Any],
    tool_env_map: dict[str, tuple[int, str, dict[str, Any]]],
    policy_engine: ProgentPolicyEngine,
    policy: list[dict[str, Any]],
    policy_error: str,
    tool_name: str,
    arguments: dict[str, Any],
    tool_call_id: str,
    round_index: int,
    fail_open: bool,
) -> tuple[Any, dict[str, Any]]:
    env_entry = tool_env_map.get(tool_name)
    if env_entry is None:
        result = {"success": False, "message": f"Tool {tool_name} doesn't exist."}
        return result, _trace(case, round_index, tool_call_id, tool_name, arguments, "invalid_tool", False, ["PROGENT-INVALID-TOOL"], result)

    env_idx, env_name, _env_info = env_entry
    decision = "allow"
    execute = True
    reason_codes = ["PROGENT-POLICY-ALLOW"]
    if policy_error and not fail_open:
        decision = "block"
        execute = False
        reason_codes = ["PROGENT-POLICY-GENERATION-FAILED"]
    else:
        try:
            policy_engine.check_tool_call(policy=policy, tool_name=tool_name, arguments=arguments)
        except ProgentPolicyError as exc:
            if fail_open:
                reason_codes = ["PROGENT-POLICY-CHECK-FAILED-OPEN"]
            else:
                decision = "block"
                execute = False
                reason_codes = ["PROGENT-POLICY-BLOCK"]
                policy_error = str(exc)

    if execute:
        result = _call_env_tool_safely(envs[env_idx], tool_name, arguments)
    else:
        result = {
            "success": False,
            "message": (
                "Progent blocked this tool call before execution because it is not allowed by "
                f"the generated least-privilege policy. {policy_error}"
            ).strip(),
        }
    trace = _trace(case, round_index, tool_call_id, tool_name, arguments, decision, execute, reason_codes, result)
    trace["env_name"] = env_name
    if policy_error:
        trace["policy_error"] = policy_error
    return result, trace


def _evaluate_case_worker(*, case: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    _load_dotenv(Path(args.env_file) if args.env_file else Path(".env"))
    _add_upstream_paths(Path(args.upstream_dir).resolve())
    from EnvManager import EnvManager  # type: ignore[import-not-found]

    api = _build_agent(_agent_args_for_model(args))
    policy_engine = _build_policy_engine(args)
    return evaluate_case(
        case=case,
        api=api,
        policy_engine=policy_engine,
        env_manager=EnvManager(),
        max_rounds=args.max_rounds,
        fail_open=args.policy_fail_open,
    )


def _build_policy_engine(args: argparse.Namespace) -> ProgentPolicyEngine:
    api_key_env = args.policy_api_key_env or args.api_key_env
    api_key = os.getenv(api_key_env) or os.getenv(args.api_key_env) or os.getenv("OPENAI_API_KEY") or os.getenv("DASHSCOPE_API_KEY")
    if not api_key:
        raise RuntimeError(f"Missing Progent policy API key. Set {api_key_env}.")
    base_url = args.policy_base_url or args.base_url or os.getenv("OPENAI_BASE_URL") or os.getenv("DASHSCOPE_BASE_URL") or "https://api.openai.com/v1"
    return ProgentPolicyEngine(
        progent_dir=Path(args.progent_dir).resolve(),
        model=args.policy_model or args.model,
        api_key=api_key,
        base_url=base_url,
        timeout=args.timeout,
        max_tokens=args.policy_max_tokens,
    )


def _agent_args_for_model(args: argparse.Namespace) -> argparse.Namespace:
    model_args = argparse.Namespace(**vars(args))
    model_args.defense = "none"
    return model_args


def _load_progent_asb_prompt(progent_dir: Path) -> str:
    os.environ["SECAGENT_TASK_TYPE"] = "asb"
    os.environ.setdefault("SECAGENT_POLICY_MODEL", "Qwen/Qwen2.5-72B-Instruct")
    path = str(progent_dir.resolve())
    if path not in sys.path:
        sys.path.insert(0, path)
    from secagent import tool as secagent_tool  # type: ignore[import-not-found]

    prompt = secagent_tool.get_SYS_PROMPT()
    if "Output format:" not in prompt:
        prompt += '\nOutput format: ```json [{"name": tool_name, "args": restrictions}, ...] ```'
    return prompt


def _to_progent_tools(tool_descs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for tool in tool_descs:
        params = tool.get("parameters") if isinstance(tool.get("parameters"), dict) else {}
        props = params.get("properties") if isinstance(params.get("properties"), dict) else {}
        out.append(
            {
                "name": str(tool.get("name", "")),
                "description": str(tool.get("description", "")),
                "args": deepcopy(props),
            }
        )
    return out


def _case_user_query(case: dict[str, Any]) -> str:
    if "dialog" not in case:
        return str(case.get("instruction", ""))
    parts = []
    for message in case.get("dialog") or []:
        if isinstance(message, dict) and message.get("role") == "user":
            parts.append(str(message.get("content", "")))
    return "\n".join(parts) or str(case.get("instruction", ""))


def _extract_progent_json(text: str) -> Any:
    stripped = str(text or "").strip()
    if not stripped:
        raise ValueError("empty policy response")
    if stripped.lower().startswith("no"):
        return None
    match = re.search(r"```(?:json)?\s*(.*?)```", stripped, re.S | re.I)
    candidates = [match.group(1).strip()] if match else []
    candidates.append(stripped[3:].strip() if stripped.lower().startswith("yes") else stripped)
    array_match = re.search(r"\[.*\]", stripped, re.S)
    if array_match:
        candidates.append(array_match.group(0))
    last_error: Exception | None = None
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
    raise ValueError(f"could not parse Progent policy JSON: {last_error}")


def _check_arg(arg_name: str, value: Any, restriction: Any) -> None:
    if isinstance(restriction, dict):
        validate(instance=value, schema=restriction)
    elif isinstance(restriction, str):
        if not re.match(restriction, str(value)):
            raise ProgentPolicyError(f"Invalid value for argument '{arg_name}' value '{value}', allowed pattern '{restriction}'")
    else:
        raise ProgentPolicyError(f"Unsupported restriction type for argument '{arg_name}': {type(restriction).__name__}")


def _trace(
    case: dict[str, Any],
    round_index: int,
    tool_call_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    decision: str,
    execute: bool,
    reason_codes: list[str],
    result: Any,
) -> dict[str, Any]:
    return {
        "case_id": case.get("id"),
        "round": round_index,
        "tool_call_id": tool_call_id,
        "tool_name": tool_name,
        "arguments": arguments,
        "risks": case.get("risks") or [],
        "failure_modes": case.get("failure_modes"),
        "fulfillable": case.get("fulfillable"),
        "decision": decision,
        "execute": execute,
        "reason_codes": reason_codes,
        "result_preview": _preview(result),
    }


def _append_traces(path: Path, traces: list[dict[str, Any]]) -> None:
    if not traces:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for trace in traces:
            fh.write(json.dumps(trace, ensure_ascii=False, default=str) + "\n")


def summarize_progent_run(
    gen_res: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    started: float,
    args: argparse.Namespace,
) -> dict[str, Any]:
    traces = [trace for item in gen_res for trace in item.get("progent_tool_traces", [])]
    decisions = Counter(str(t.get("decision")) for t in traces)
    executed = sum(1 for t in traces if t.get("execute"))
    blocked = sum(1 for t in traces if str(t.get("decision")) == "block")
    policy_errors = sum(1 for item in gen_res if item.get("progent_policy_error"))
    return {
        "benchmark": "Agent-SafetyBench",
        "method": "Progent",
        "model": args.model,
        "policy_model": args.policy_model or args.model,
        "cases": len(gen_res),
        "errors": len(errors),
        "total_runtime_sec": round(time.perf_counter() - started, 3),
        "policy_generation_errors": policy_errors,
        "total_tool_calls": len(traces),
        "executed_tool_calls": executed,
        "blocked_tool_calls": blocked,
        "decision_counts": dict(sorted(decisions.items())),
        "tool_execution_rate": 0.0 if not traces else executed / len(traces),
        "tool_block_rate": 0.0 if not traces else blocked / len(traces),
        "output_files": {
            "gen_res": str(Path(args.out_dir).resolve() / "gen_res.json"),
            "progent_trace": str(Path(args.out_dir).resolve() / "progent_trace.jsonl"),
            "summary_json": str(Path(args.out_dir).resolve() / "summary.json"),
            "summary_md": str(Path(args.out_dir).resolve() / "summary.md"),
        },
    }


def render_summary(summary: dict[str, Any]) -> str:
    lines = [
        "# Agent-SafetyBench + Progent",
        "",
        f"- Benchmark: {summary['benchmark']}",
        f"- Method: `{summary['method']}`",
        f"- Model: `{summary['model']}`",
        f"- Policy model: `{summary['policy_model']}`",
        f"- Cases: {summary['cases']}",
        f"- Policy generation errors: {summary['policy_generation_errors']}",
        f"- Total tool calls: {summary['total_tool_calls']}",
        f"- Tool block rate: {summary['tool_block_rate']:.2%}",
        f"- Tool execution rate: {summary['tool_execution_rate']:.2%}",
        "",
        "## Decisions",
        "",
    ]
    for key, value in summary["decision_counts"].items():
        lines.append(f"- `{key}`: {value}")
    return "\n".join(lines) + "\n"


def _progress_line(done: int, total: int, case: dict[str, Any], result: dict[str, Any]) -> str:
    traces = result.get("progent_tool_traces", [])
    counts = Counter(str(t.get("decision")) for t in traces)
    return f"[{done}/{total}] id={case.get('id')} rounds={result.get('rounds')} tool_calls={len(traces)} decisions={dict(counts)}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Agent-SafetyBench with Progent tool gating")
    parser.add_argument("--upstream-dir", default=str(DEFAULT_UPSTREAM))
    parser.add_argument("--data", default=str(DEFAULT_DATA))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--progent-dir", default=str(DEFAULT_PROGENT))
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--api-key-env", default="DASHSCOPE_API_KEY")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--policy-model", default="")
    parser.add_argument("--policy-api-key-env", default="")
    parser.add_argument("--policy-base-url", default="")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--policy-max-tokens", type=int, default=2048)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-rounds", type=int, default=10)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--case-ids", default="")
    parser.add_argument("--risk-contains", default="")
    parser.add_argument("--enable-thinking", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--policy-fail-open", action="store_true", help="If policy generation/checking fails, execute tools instead of blocking.")
    return parser.parse_args()


def main() -> None:
    summary = run(parse_args())
    print(json.dumps(summary, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
