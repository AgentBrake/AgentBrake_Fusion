"""Small structured profiler used by gateway evaluation runs."""

from __future__ import annotations

from contextlib import contextmanager
from time import perf_counter
from typing import Iterator


class EvalProfiler:
    def __init__(self) -> None:
        self.timings: dict[str, float] = {}

    @contextmanager
    def span(self, name: str) -> Iterator[None]:
        start = perf_counter()
        try:
            yield
        finally:
            self.add(name, (perf_counter() - start) * 1000)

    def add(self, name: str, elapsed_ms: float) -> None:
        self.timings[name] = self.timings.get(name, 0.0) + elapsed_ms

    def as_event(self) -> dict[str, object]:
        return {
            "type": "performance_trace",
            "timings_ms": {name: round(value, 3) for name, value in sorted(self.timings.items())},
        }
