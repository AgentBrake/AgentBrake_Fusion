"""Runtime feature flags for backward-compatible architecture upgrades."""

from __future__ import annotations

import os


def feature_enabled(name: str, *, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}
