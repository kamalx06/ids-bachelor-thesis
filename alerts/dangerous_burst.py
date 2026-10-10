"""
Rate-limited email alerts when a single source IP exceeds a burst of high-risk
events within a rolling time window.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict

from alerts.email_alert import send_alert

_WINDOW_SEC = int(os.getenv("IDS_BURST_ALERT_WINDOW_SEC", str(20 * 60)) or (20 * 60))
_THRESHOLD = int(os.getenv("IDS_BURST_ALERT_MIN_EVENTS", "10") or "10")
_DEDUP_SEC = int(os.getenv("IDS_BURST_ALERT_DEDUP_SEC", str(10 * 60)) or (10 * 60))
_DANGEROUS_RISK = float(os.getenv("IDS_DANGEROUS_THRESHOLD", "0.78") or "0.78")

_LOCK = threading.Lock()
_EVENTS: dict[str, list[tuple[float, frozenset[str]]]] = defaultdict(list)
_LAST_EMAIL: dict[str, float] = {}

# Drop idle IPs from both maps once every this many calls, so a spoofed-source
# scan doesn't leave the process holding per-IP state forever.
_EVICT_EVERY = 5000
_evict_counter = 0

# The longest a piece of per-IP state is useful. Events older than the burst
# window are already dropped on every call; the last-email timestamp is only
# useful for _DEDUP_SEC. Keep whichever is longer.
_MAX_IDLE_SEC = max(_WINDOW_SEC, _DEDUP_SEC)


def _burst_eligible(classification: str | None, risk_score: float | None) -> bool:
    c = (classification or "").lower()
    if c == "dangerous":
        return True
    if c == "suspicious" and risk_score is not None and float(risk_score) >= _DANGEROUS_RISK:
        return True
    return False


def _evict_idle_locked(now: float) -> None:
    """Drop IPs whose last event is older than the useful window.

    Called under _LOCK by maybe_alert_dangerous_burst every _EVICT_EVERY
    calls, so the sweep is amortized and doesn't block the alerting hot path.
    """
    stale_cutoff = now - _MAX_IDLE_SEC
    stale_ips = [
        ip
        for ip, events in _EVENTS.items()
        if not events or events[-1][0] < stale_cutoff
    ]
    for ip in stale_ips:
        _EVENTS.pop(ip, None)
        _LAST_EMAIL.pop(ip, None)


def _threat_types(reasons: list | None) -> frozenset[str]:
    out: set[str] = set()
    if not reasons:
        return frozenset()
    for r in reasons:
        if not isinstance(r, str) or not r.strip():
            continue
        out.add(r.strip())
    return frozenset(out)


def maybe_alert_dangerous_burst(
    *,
    src_ip: str | None,
    classification: str | None,
    risk_score: float | None,
    reasons: list | None,
) -> None:
    if not src_ip:
        return
    if not _burst_eligible(classification, risk_score):
        return

    global _evict_counter

    now = time.time()
    cutoff = now - _WINDOW_SEC
    types = _threat_types(reasons)

    with _LOCK:
        _evict_counter += 1
        if _evict_counter % _EVICT_EVERY == 0:
            _evict_idle_locked(now)

        bucket = _EVENTS[src_ip]
        bucket.append((now, types))
        bucket[:] = [(t, ts) for t, ts in bucket if t >= cutoff]

        if len(bucket) <= _THRESHOLD:
            return

        last = _LAST_EMAIL.get(src_ip, 0.0)
        if now - last < _DEDUP_SEC:
            return

        _LAST_EMAIL[src_ip] = now
        count = len(bucket)
        merged: set[str] = set()
        for _, ts in bucket:
            merged.update(ts)

    lines = [
        f"IP address: {src_ip}",
        f"Dangerous / high-risk events in the last {_WINDOW_SEC // 60} minutes: {count}",
        f"(Alert fires when more than {_THRESHOLD} such events occur in that rolling window.)",
        "",
        "Threat / reason signals observed in this window (deduplicated):",
    ]
    if merged:
        for item in sorted(merged)[:80]:
            lines.append(f"  - {item}")
    else:
        lines.append("  (no structured threat types; see IDS logs for full context)")

    try:
        send_alert(
            f"[IDS] Burst alert: {src_ip} ({count} high-risk events / {_WINDOW_SEC // 60} min)",
            "\n".join(lines),
        )
    except Exception:
        # send_alert is contractually non-raising; this guard exists only
        # so a future change to that contract cannot crash the packet
        # analysis worker.
        from logging_config import get_logger
        get_logger(__name__).error(
            "Burst alert delivery raised despite send_alert's contract",
            exc_info=True,
        )
