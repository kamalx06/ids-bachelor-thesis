"""
Resolve log / event epoch seconds from explicit sources (wire time, device, etc.)
without shifting or double-converting timezones. All values are treated as UTC epoch.

Priority (first valid wins):
  1. packet_send_time
  2. event_origin_time
  3. device_timestamp
  4. fallback_ingestion_time (e.g. already-resolved capture envelope time)
  5. time.time() only if nothing else is valid (DB must not get NULL).
"""

from __future__ import annotations

import math
import time
from typing import Any


def _coerce_epoch_seconds(value: Any) -> float | None:
    if value is None:
        return None
    try:
        if hasattr(value, "item") and callable(value.item):
            try:
                value = value.item()
            except Exception:
                pass
        f = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(f) or f <= 0:
        return None
    # Heuristic: epoch in milliseconds (common in JSON / some APIs) vs seconds.
    if f > 1e12:
        f *= 1e-3
    return f


def resolve_event_epoch_seconds(
    *,
    packet_send_time: Any = None,
    event_origin_time: Any = None,
    device_timestamp: Any = None,
    fallback_ingestion_time: Any = None,
) -> float:
    for candidate in (packet_send_time, event_origin_time, device_timestamp):
        ts = _coerce_epoch_seconds(candidate)
        if ts is not None:
            return ts
    fb = _coerce_epoch_seconds(fallback_ingestion_time)
    if fb is not None:
        return fb
    return time.time()


def scapy_packet_epoch_seconds(pkt: Any) -> float | None:
    """Libpcap / kernel timestamp for the frame (passive capture 'wire' time)."""
    t = getattr(pkt, "time", None)
    return _coerce_epoch_seconds(t)
