"""Opt-in, bounded operation-level timing statistics for synthetic INNERnet trials.

No payloads, URLs, capabilities, token values, or per-object identifiers are
collected. Concurrent phases can overlap: do NOT add their wall-clock totals.
"""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager, nullcontext


class OperationProfiler:
    def __init__(self, enabled: bool = False):
        if type(enabled) is not bool:
            raise ValueError("profiling must be enabled or disabled explicitly")
        self.enabled = enabled
        self._lock = threading.Lock()
        self._records: dict[str, list[int]] = {}

    def span(self, stage: str):
        if not self.enabled:
            return nullcontext()
        if not stage or len(stage) > 64 or not all(c.isalnum() or c in "._-" for c in stage):
            raise ValueError("invalid profiling stage name")
        return self._measure(stage)

    @contextmanager
    def _measure(self, stage: str):
        started = time.perf_counter_ns()
        try:
            yield
        finally:
            elapsed = max(time.perf_counter_ns() - started, 0)
            with self._lock:
                rec = self._records.setdefault(stage, [0, 0, 0])
                rec[0] += 1
                rec[1] += elapsed
                rec[2] = max(rec[2], elapsed)

    def snapshot(self) -> dict:
        if not self.enabled:
            return {"enabled": False, "stages": {}}
        with self._lock:
            records = {key: tuple(rec) for key, rec in self._records.items()}
        return {
            "enabled": True,
            "unit": "milliseconds",
            "stages": {
                name: {"calls": count, "cumulative_ms": round(total / 1_000_000, 3),
                       "mean_ms": round(total / count / 1_000_000, 3),
                       "max_ms": round(maximum / 1_000_000, 3)}
                for name, (count, total, maximum) in sorted(records.items())
            },
            "note": "Concurrent and nested stages overlap; cumulative timings are not total wall time. "
                    "No secrets, payload bytes, paths, or node addresses are captured.",
        }
