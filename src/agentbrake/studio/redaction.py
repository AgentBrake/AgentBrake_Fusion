"""Display-time redaction helpers for Studio Pro."""

from __future__ import annotations

import json
import re
from typing import Any

TOKEN_RE = re.compile(r"(ghp_[A-Za-z0-9_\-]{10,}|npm_[A-Za-z0-9_\-]{8,}|sk-[A-Za-z0-9_\-]{16,}|RS_CANARY_[A-Z0-9_]+)")
KV_RE = re.compile(r"(?i)(password|token|secret|api_key|authorization)=([^\s&\"']+)")
SENSITIVE_KEY_RE = re.compile(r"(?i)(password|token|secret|api[_-]?key|apikey|authorization|auth)")


def redact_value(value: Any, max_text: int = 8000) -> Any:
    """Recursively redact payloads before they are exposed through Studio APIs."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            if key == "contentBase64" and isinstance(v, str):
                redacted[key] = TOKEN_RE.sub("<REDACTED_TOKEN>", v)
                continue
            redacted[key] = "<REDACTED>" if SENSITIVE_KEY_RE.search(key) and v else redact_value(v, max_text=max_text)
        return redacted
    if isinstance(value, list):
        return [redact_value(v, max_text=max_text) for v in value]
    if isinstance(value, str):
        text = TOKEN_RE.sub("<REDACTED_TOKEN>", value)
        text = KV_RE.sub(r"\1=<REDACTED>", text)
        if len(text) > max_text:
            return text[:max_text] + f"...<TRUNCATED {len(text) - max_text} chars>"
        return text
    return value


def redacted_json(data: Any) -> str:
    return json.dumps(redact_value(data), ensure_ascii=False, sort_keys=True, default=str)
