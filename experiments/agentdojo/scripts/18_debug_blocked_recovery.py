from __future__ import annotations

import argparse
import ast
import json
from collections import Counter
from pathlib import Path
from typing import Any

DEFAULT_CASES = [
    "banking:user_task_2:injection_task_0",
    "banking:user_task_2:injection_task_1",
    "banking:user_task_2:injection_task_2",
    "banking:user_task_2:injection_task_3",
    "slack:user_task_1:injection_task_1",
    "slack:user_task_1:injection_task_2",
    "slack:user_task_2:injection_task_1",
    "slack:user_task_2:injection_task_2",
    "travel:user_task_1:injection_task_0",
    "travel:user_task_1:injection_task_2",
    "travel:user_task_3:injection_task_0",
    "travel:user_task_3:injection_task_1",
    "travel:user_task_3:injection_task_2",
    "travel:user_task_3:injection_task_3",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Debug AgentBrake-Fusion blocked recovery cases from AgentDojo paired raw reports")
    parser.add_argument("--reports-dir", type=Path, required=True)
    parser.add_argument("--trace-dir", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--case", action="append", default=None)
    args = parser.parse_args()
    analyses = analyze_blocked_cases(args.reports_dir, selectors=args.case or DEFAULT_CASES, trace_dir=args.trace_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.out_dir / "blocked_case_analysis.jsonl", analyses)
    (args.out_dir / "blocked_case_analysis.md").write_text(render_markdown(analyses), encoding="utf-8")
    write_json(args.out_dir / "recovery_failure_taxonomy.json", taxonomy(analyses))
    write_jsonl(args.out_dir / "trace_missing_cases.jsonl", [row for row in analyses if row["failure_category"] == "missing_trace"])
    print(args.out_dir / "blocked_case_analysis.md")
    return 0


def analyze_blocked_cases(reports_dir: Path, *, selectors: list[str], trace_dir: Path | None = None) -> list[dict[str, Any]]:
    patterns = [parse_selector(selector) for selector in selectors]
    analyses: list[dict[str, Any]] = []
    for summary_path, summary in iter_summaries(reports_dir):
        for row in summary.get("per_run") or summary.get("normalized_cases") or []:
            if not isinstance(row, dict) or not bool(row.get("blocked_case")):
                continue
            suite = str(row.get("suite") or summary.get("suite") or "")
            user_task_id = str(row.get("user_task_id") or "")
            injection_task_id = str(row.get("injection_task_id") or "")
            if not matches_any(patterns, suite, user_task_id, injection_task_id):
                continue
            trace_path = resolve_trace_path(row.get("trace_file"), summary_path, trace_dir)
            trace = load_trace(trace_path)
            if not has_full_trace(trace):
                analyses.append(base_analysis(summary_path, row, suite, user_task_id, injection_task_id, trace_path, "missing_trace"))
                continue
            analyses.append(analyze_with_trace(summary_path, row, suite, user_task_id, injection_task_id, trace_path, trace))
    return analyses


def analyze_with_trace(
    summary_path: Path,
    row: dict[str, Any],
    suite: str,
    user_task_id: str,
    injection_task_id: str,
    trace_path: Path | None,
    trace: dict[str, Any],
) -> dict[str, Any]:
    events = [event for event in trace.get("audit_events") or [] if isinstance(event, dict)]
    blocked = first_block_event(events)
    post_block_calls = post_block_tool_calls(trace.get("tool_calls") or [], row.get("first_block_step"))
    next_assistant = next_assistant_message_after(trace.get("messages") or [], blocked)
    category = classify_failure(row, blocked, post_block_calls)
    safe_result = blocked_safe_result(blocked, trace.get("tool_results") or [], row.get("first_block_step"))
    result = base_analysis(summary_path, row, suite, user_task_id, injection_task_id, trace_path, category)
    result.update(
        {
            "trace_status": "full_trace_available",
            "first_block_event": summarize_event(blocked),
            "blocked_tool": safe_result.get("blocked_tool") or ((blocked.get("evidence") or {}).get("agentdojo.tool_name") if isinstance(blocked, dict) else None),
            "decision": blocked.get("decision") if isinstance(blocked, dict) else None,
            "reason_codes": blocked.get("reason_codes") if isinstance(blocked, dict) else [],
            "blocked_result_text": safe_result.get("message") or safe_result.get("human_readable_reason"),
            "allowed_next_steps": safe_result.get("allowed_next_steps") or [],
            "disallowed_next_steps": safe_result.get("disallowed_next_steps") or [],
            "confirmation_executed": bool(blocked.get("confirmation_executed")) if isinstance(blocked, dict) else False,
            "next_assistant_message": next_assistant,
            "post_block_tool_call_count_from_trace": len(post_block_calls),
            "next_tool_call_after_block": post_block_calls[0] if post_block_calls else None,
        }
    )
    return result


def classify_failure(row: dict[str, Any], blocked: dict[str, Any] | None, post_block_calls: list[dict[str, Any]]) -> str:
    if int(row.get("repeated_block_count") or 0) > 0:
        return "repeated_same_blocked_action"
    if int(row.get("confirmation_required_count") or 0) and not int(row.get("confirmation_executed_count") or 0):
        return "confirmation_not_executed"
    if is_injected_or_private_block(blocked):
        return "blocked_injected_action_recovery_failed"
    safe_result = blocked.get("safe_result") if isinstance(blocked, dict) else None
    if isinstance(safe_result, dict) and not safe_result.get("allowed_next_steps"):
        return "guidance_too_generic"
    if not post_block_calls:
        return "model_stopped_after_block"
    if row.get("final_user_task_success") is False and row.get("final_injection_task_success") is False:
        return "policy_overblocked_user_authorized_action"
    return "blocked_recovery_needs_review"


def blocked_safe_result(blocked: dict[str, Any] | None, tool_results: list[Any], first_block_step: Any) -> dict[str, Any]:
    if isinstance(blocked, dict):
        for key in ("safe_result", "safe_blocked_result", "blocked_result"):
            value = blocked.get(key)
            if isinstance(value, dict):
                return value
        metadata = blocked.get("decision_metadata")
        if isinstance(metadata, dict):
            for key in ("safe_result", "safe_blocked_result", "blocked_result"):
                value = metadata.get(key)
                if isinstance(value, dict):
                    return value
    try:
        min_step = int(first_block_step)
    except Exception:
        min_step = -1
    candidates = []
    for result in tool_results:
        if not isinstance(result, dict):
            continue
        try:
            step = int(result.get("step") or -1)
        except Exception:
            step = -1
        if min_step >= 0 and step < min_step:
            continue
        parsed = parse_blocked_tool_result(result.get("content"))
        if parsed:
            candidates.append((step, parsed))
    if candidates:
        return sorted(candidates, key=lambda item: item[0])[0][1]
    return {}


def parse_blocked_tool_result(content: Any) -> dict[str, Any]:
    texts: list[str] = []
    if isinstance(content, str):
        texts.append(content)
    elif isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                value = item.get("content") or item.get("text")
                if isinstance(value, str):
                    texts.append(value)
            elif isinstance(item, str):
                texts.append(item)
    elif isinstance(content, dict):
        value = content.get("content") or content.get("text")
        if isinstance(value, str):
            texts.append(value)
    for text in texts:
        if "blocked_tool" not in text and "allowed_next_steps" not in text:
            continue
        for loader in (json.loads, ast.literal_eval):
            try:
                parsed = loader(text)
            except Exception:
                continue
            if isinstance(parsed, dict) and (parsed.get("blocked_tool") or parsed.get("allowed_next_steps")):
                return parsed
    return {}


def is_injected_or_private_block(blocked: dict[str, Any] | None) -> bool:
    if not isinstance(blocked, dict):
        return False
    reason_codes = {str(code) for code in blocked.get("reason_codes") or []}
    if any(marker in code for code in reason_codes for marker in ("INJECTED", "PRIVATE-EXFIL", "GOAL", "GRAPH")):
        evidence = blocked.get("evidence") or {}
        if not isinstance(evidence, dict):
            return True
        return bool(
            evidence.get("agentdojo.args_match_untrusted_entity")
            or evidence.get("agentdojo.attack_goal_overlap")
            or evidence.get("graph.has_attack_goal_to_action_edge")
            or evidence.get("graph.has_private_to_external_edge")
            or evidence.get("graph.has_injection_to_side_effect_edge")
        )
    return False


def first_block_event(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in events:
        if event.get("event_type") != "agentdojo_tool_gate_decision":
            continue
        if not bool(event.get("execute")) and event.get("decision") in {"block", "quarantine", "require_confirmation", "sandbox_then_approval"}:
            return event
    return None


def next_assistant_message_after(messages: list[Any], blocked: dict[str, Any] | None) -> str | None:
    if not isinstance(blocked, dict):
        return None
    # Audit events do not carry message indexes. Use the first assistant message
    # after a blocked result-like tool message as a conservative recovery signal.
    saw_blocked_tool_result = False
    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("role") == "tool" and "AgentBrake-Fusion" in json.dumps(message.get("content"), ensure_ascii=False, default=str):
            saw_blocked_tool_result = True
            continue
        if saw_blocked_tool_result and message.get("role") == "assistant":
            return json.dumps(message.get("content"), ensure_ascii=False, default=str)
    return None


def post_block_tool_calls(tool_calls: list[Any], first_block_step: Any) -> list[dict[str, Any]]:
    try:
        step = int(first_block_step)
    except Exception:
        return [call for call in tool_calls if isinstance(call, dict)]
    return [call for call in tool_calls if isinstance(call, dict) and int(call.get("step") or 0) > step]


def base_analysis(
    summary_path: Path,
    row: dict[str, Any],
    suite: str,
    user_task_id: str,
    injection_task_id: str,
    trace_path: Path | None,
    failure_category: str,
) -> dict[str, Any]:
    return {
        "source_raw_file": str(summary_path),
        "suite": suite,
        "method": row.get("method"),
        "user_task_id": user_task_id,
        "injection_task_id": injection_task_id,
        "trace_file": str(trace_path) if trace_path else None,
        "trace_status": "missing_full_trace" if failure_category == "missing_trace" else "unknown",
        "failure_category": failure_category,
        "raw_agentdojo_user_task_success": bool(row.get("raw_agentdojo_user_task_success", row.get("utility", False))),
        "raw_agentdojo_injection_task_success": bool(row.get("raw_agentdojo_injection_task_success", row.get("security", False))),
        "first_block_step": row.get("first_block_step"),
        "repeated_block_count": int(row.get("repeated_block_count") or 0),
        "confirmation_required_count": int(row.get("confirmation_required_count") or 0),
        "confirmation_executed_count": int(row.get("confirmation_executed_count") or 0),
        "required_action": required_action(failure_category),
    }


def required_action(category: str) -> str:
    return {
        "missing_trace": "rerun with --save-full-trace and re-run this debugger",
        "repeated_same_blocked_action": "strengthen blocked-result do-not-retry guidance and model recovery prompt",
        "confirmation_not_executed": "use oracle_user_eval for user-authorized confirmation or make confirmation routing explicit",
        "guidance_too_generic": "add concrete trusted-data recovery steps to safe_result",
        "model_stopped_after_block": "inspect final assistant behavior and add continuation guidance",
        "blocked_injected_action_recovery_failed": "keep the block and improve post-block trusted-data recovery steps",
        "policy_overblocked_user_authorized_action": "adjust suite policy to require confirmation rather than hard block",
    }.get(category, "manual review")


def taxonomy(analyses: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(row["failure_category"] for row in analyses)
    return {"case_count": len(analyses), "categories": dict(sorted(counts.items()))}


def render_markdown(analyses: list[dict[str, Any]]) -> str:
    lines = [
        "# Blocked Recovery Analysis",
        "",
        "## Taxonomy Summary",
        "",
        "| failure_category | count |",
        "|---|---:|",
    ]
    counts = Counter(row["failure_category"] for row in analyses)
    for category, count in sorted(counts.items()):
        lines.append(f"| {category} | {count} |")
    lines.extend(["", "## Per-Suite Failure Table", "", "| suite | failure_category | count |", "|---|---|---:|"])
    suite_counts = Counter((str(row["suite"]), str(row["failure_category"])) for row in analyses)
    for (suite, category), count in sorted(suite_counts.items()):
        lines.append(f"| {suite} | {category} | {count} |")
    lines.extend(
        [
            "",
            "## Case Details",
            "",
            "| suite | user_task_id | injection_task_id | blocked_tool | decision | reason_codes | next_behavior | category | required_action |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for row in analyses:
        next_behavior = row.get("next_assistant_message") or row.get("next_tool_call_after_block") or "none"
        if not isinstance(next_behavior, str):
            next_behavior = json.dumps(next_behavior, ensure_ascii=False, default=str)
        next_behavior = next_behavior.replace("|", "\\|").replace("\n", " ")[:180]
        reason_codes = ", ".join(str(code) for code in row.get("reason_codes") or [])
        lines.append(
            f"| {row['suite']} | {row['user_task_id']} | {row['injection_task_id']} | {row.get('blocked_tool')} | {row.get('decision')} | {reason_codes} | {next_behavior} | {row['failure_category']} | {row['required_action']} |"
        )
    if not analyses:
        lines.extend(["", "No matching blocked cases were found."])
    else:
        lines.extend(["", "## Per-Suite Repair Recommendations", ""])
        for suite in sorted({str(row["suite"]) for row in analyses}):
            suite_rows = [row for row in analyses if row["suite"] == suite]
            categories = Counter(row["failure_category"] for row in suite_rows)
            actions = []
            for row in suite_rows:
                action = str(row.get("required_action") or "manual review")
                if action not in actions:
                    actions.append(action)
            lines.append(f"- {suite}: {', '.join(f'{k}={v}' for k, v in sorted(categories.items()))}. Recommended: {'; '.join(actions)}.")
        missing = [row for row in analyses if row.get("trace_status") == "missing_full_trace"]
        lines.extend(["", "## Trace Missing List", ""])
        if missing:
            for row in missing:
                lines.append(f"- {row['suite']}:{row['user_task_id']}:{row['injection_task_id']} -> rerun with --save-full-trace")
        else:
            lines.append("- None; trace_missing_cases.jsonl is present and empty.")
        lines.extend(
            [
                "",
                "## Current Recovery Status",
                "",
                "This debug report identifies remaining recovery failure categories in the full paired-mini traces; it does not by itself claim full paired-mini recovery is fixed.",
            ]
        )
    return "\n".join(lines) + "\n"


def summarize_event(event: dict[str, Any] | None) -> dict[str, Any] | None:
    if not event:
        return None
    return {
        "tool_name": event.get("tool_name"),
        "decision": event.get("decision"),
        "execute": event.get("execute"),
        "reason_codes": event.get("reason_codes"),
        "confirmation_required": event.get("confirmation_required"),
        "confirmation_executed": event.get("confirmation_executed"),
    }


def parse_selector(selector: str) -> tuple[str, str, str]:
    parts = selector.split(":")
    if len(parts) != 3:
        raise ValueError(f"case selector must be suite:user_task_id:injection_task_id, got {selector!r}")
    return parts[0], parts[1], parts[2]


def matches_any(patterns: list[tuple[str, str, str]], suite: str, user: str, injection: str) -> bool:
    return any(part_matches(a, suite) and part_matches(u, user) and part_matches(i, injection) for a, u, i in patterns)


def part_matches(pattern: str, value: str) -> bool:
    if pattern == "*":
        return True
    return pattern == value or value.endswith(pattern) or pattern.endswith(value)


def iter_summaries(reports_dir: Path) -> Any:
    for path in sorted(reports_dir.rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and (data.get("per_run") or data.get("normalized_cases")):
            yield path, data


def resolve_trace_path(raw: Any, summary_path: Path, trace_dir: Path | None = None) -> Path | None:
    if not raw:
        return None
    path = Path(str(raw))
    if path.is_absolute() or path.exists():
        return path
    candidate = summary_path.parent / path
    if candidate.exists():
        return candidate
    if trace_dir:
        tail = Path(*path.parts[-4:]) if len(path.parts) >= 4 else path
        candidate = trace_dir / tail
        if candidate.exists():
            return candidate
    return path


def load_trace(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def has_full_trace(trace: dict[str, Any] | None) -> bool:
    return bool(isinstance(trace, dict) and isinstance(trace.get("messages"), list) and isinstance(trace.get("tool_calls"), list) and isinstance(trace.get("tool_results"), list))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows) + ("\n" if rows else ""), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
