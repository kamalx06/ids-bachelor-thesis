"""
Prometheus-compatible metrics (text exposition format).
"""

from __future__ import annotations

import threading
from typing import Any

_lock = threading.Lock()
_counters: dict[str, float] = {}
_gauges: dict[str, float] = {}


def inc(name: str, value: float = 1.0, labels: dict[str, str] | None = None) -> None:
    key = _key(name, labels)
    with _lock:
        _counters[key] = _counters.get(key, 0.0) + value


def set_gauge(name: str, value: float, labels: dict[str, str] | None = None) -> None:
    key = _key(name, labels)
    with _lock:
        _gauges[key] = value


def _key(name: str, labels: dict[str, str] | None) -> str:
    if not labels:
        return name
    parts = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return f"{name}{{{parts}}}"


def export_prometheus() -> str:
    lines: list[str] = []
    with _lock:
        for key, val in sorted(_counters.items()):
            lines.append(f"# TYPE {key.split('{')[0]} counter")
            lines.append(f"{key} {val}")
        for key, val in sorted(_gauges.items()):
            lines.append(f"# TYPE {key.split('{')[0]} gauge")
            lines.append(f"{key} {val}")
    return "\n".join(lines) + "\n"
