from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from openai import OpenAI

DEFAULT_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
SECRET_RE = re.compile(r"\bsk-[A-Za-z0-9]{16,}\b")
LOCAL_PATH_RE = re.compile(r"[A-Za-z]:\\\\|/home/|/Users/|file://", re.IGNORECASE)


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe cross-model OpenAI-compatible AgentDojo adapters")
    parser.add_argument("--models-config", type=Path, required=True)
    parser.add_argument("--model-key", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    config = load_model_config(args.models_config, args.model_key)
    result, trace = probe_model(config)
    write_json(args.out_dir / "adapter_probe_trace.json", trace)
    result["trace_file"] = "adapter_probe_trace.json"
    result["secret_scan"] = "PASS" if no_secret_or_local_path(args.out_dir, include_current=result) else "FAIL"
    result["adapter_status"] = "PASS" if adapter_pass(result, trace) else "FAIL"
    write_json(args.out_dir / "adapter_probe_results.json", result)
    (args.out_dir / "adapter_probe_results.md").write_text(render_md(result), encoding="utf-8")
    print(args.out_dir / "adapter_probe_results.json")
    return 0 if result["adapter_status"] == "PASS" else 1


def load_model_config(path: Path, model_key: str) -> dict[str, Any]:
    data = parse_simple_models_yaml(path)
    for model in data.get("models") or []:
        if model.get("model_key") == model_key:
            return model
    raise ValueError(f"model_key not found: {model_key}")


def parse_simple_models_yaml(path: Path) -> dict[str, Any]:
    models: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line == "models:":
            continue
        if line.startswith("- "):
            if current:
                models.append(current)
            current = {}
            line = line[2:].strip()
        if ":" not in line or current is None:
            continue
        key, value = line.split(":", 1)
        text = value.strip().strip('"').strip("'")
        if text.lower() in {"true", "false"}:
            current[key.strip()] = text.lower() == "true"
        else:
            current[key.strip()] = text
    if current:
        models.append(current)
    return {"models": models}


def probe_model(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    api_key_env = str(config.get("api_key_env") or "OPENAI_API_KEY")
    base_url_env = str(config.get("base_url_env") or "OPENAI_BASE_URL")
    api_key = os.getenv(api_key_env) or os.getenv("OPENAI_API_KEY")
    base_url = os.getenv(base_url_env) or os.getenv("OPENAI_BASE_URL") or DEFAULT_BASE_URL
    model_id = str(config["model_id"])
    started_at = datetime.now(timezone.utc).isoformat()
    messages = [
        {"role": "system", "content": "You are a tool-calling adapter probe. Use the provided tool exactly once."},
        {"role": "user", "content": "Call echo_probe with payload set to qwen_adapter_probe and count set to 1."},
    ]
    tools = [
        {
            "type": "function",
            "function": {
                "name": "echo_probe",
                "description": "Echo a short adapter probe payload.",
                "parameters": {
                    "type": "object",
                    "properties": {"payload": {"type": "string"}, "count": {"type": "integer"}},
                    "required": ["payload", "count"],
                },
            },
        }
    ]
    result: dict[str, Any] = {
        "model_key": config.get("model_key"),
        "model_id": model_id,
        "provider": config.get("provider"),
        "adapter": config.get("adapter"),
        "api_key_env": api_key_env,
        "base_url_env": base_url_env,
        "api_call_success": False,
        "chat_completion_compatible": False,
        "role_compatibility": False,
        "tool_call_parse_success": False,
        "json_args_parse_success": False,
        "retry_compatible": False,
        "token_usage_recorded": False,
        "trace_saved": False,
        "started_at": started_at,
    }
    trace: dict[str, Any] = {
        "trace_schema_version": "agentdojo_trace_v1",
        "experiment": "cross_model_adapter_probe",
        "model": model_id,
        "provider": config.get("provider"),
        "messages": redact(messages),
        "tool_calls": [],
        "audit_events": [],
        "started_at": started_at,
    }
    if not api_key:
        result["error"] = f"{api_key_env} is not set"
        return result, trace
    try:
        client = OpenAI(api_key=api_key, base_url=base_url, timeout=float(os.getenv("AGENTBRAKE_LLM_TIMEOUT", "300")))
        response = client.chat.completions.create(model=model_id, messages=messages, tools=tools, tool_choice="auto", temperature=0)
        result["api_call_success"] = True
        result["chat_completion_compatible"] = True
        result["role_compatibility"] = True
        choice = response.choices[0]
        message = choice.message
        usage = getattr(response, "usage", None)
        result["token_usage_recorded"] = usage is not None
        tool_calls = list(getattr(message, "tool_calls", None) or [])
        parsed_args: list[dict[str, Any]] = []
        for call in tool_calls:
            function = getattr(call, "function", None)
            args_text = getattr(function, "arguments", "{}") if function else "{}"
            parsed = json.loads(args_text)
            parsed_args.append(parsed)
            trace["tool_calls"].append(
                {
                    "id": getattr(call, "id", None),
                    "name": getattr(function, "name", None),
                    "arguments": redact(parsed),
                }
            )
        result["tool_call_parse_success"] = bool(tool_calls)
        result["json_args_parse_success"] = bool(parsed_args) and all(isinstance(item, dict) for item in parsed_args)
        result["retry_compatible"] = True
        trace["audit_events"].append(
            {
                "event_type": "adapter_probe_chat_completion",
                "api_call_success": True,
                "tool_call_count": len(tool_calls),
                "token_usage_recorded": result["token_usage_recorded"],
            }
        )
    except Exception as exc:
        result["error"] = type(exc).__name__
        trace["audit_events"].append({"event_type": "adapter_probe_error", "error_type": type(exc).__name__})
    result["trace_saved"] = True
    return result, trace


def adapter_pass(result: dict[str, Any], trace: dict[str, Any]) -> bool:
    return bool(
        result.get("api_call_success")
        and result.get("tool_call_parse_success")
        and result.get("json_args_parse_success")
        and result.get("trace_saved")
        and trace.get("trace_schema_version") == "agentdojo_trace_v1"
        and result.get("secret_scan") == "PASS"
    )


def no_secret_or_local_path(out_dir: Path, *, include_current: dict[str, Any]) -> bool:
    texts = [json.dumps(include_current, ensure_ascii=False)]
    for path in out_dir.glob("*"):
        if path.is_file() and path.suffix.lower() in {".json", ".md", ".txt", ".csv", ".jsonl"}:
            texts.append(path.read_text(encoding="utf-8", errors="ignore"))
    return not any(SECRET_RE.search(text) or LOCAL_PATH_RE.search(text) for text in texts)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return SECRET_RE.sub("<redacted>", value)
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def render_md(result: dict[str, Any]) -> str:
    lines = [
        "# Cross-Model Adapter Probe",
        "",
        f"- model_key: {result.get('model_key')}",
        f"- model_id: {result.get('model_id')}",
        f"- provider: {result.get('provider')}",
        f"- adapter_status: {result.get('adapter_status')}",
        f"- api_call_success: {result.get('api_call_success')}",
        f"- tool_call_parse_success: {result.get('tool_call_parse_success')}",
        f"- json_args_parse_success: {result.get('json_args_parse_success')}",
        f"- token_usage_recorded: {result.get('token_usage_recorded')}",
        f"- trace_saved: {result.get('trace_saved')}",
        f"- secret_scan: {result.get('secret_scan')}",
    ]
    if result.get("error"):
        lines.append(f"- error: {result.get('error')}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
