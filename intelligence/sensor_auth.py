"""
HMAC request signing for the IDS sensor → web UI telemetry channel.

The previous scheme transmitted a static bearer token (X-IDS-TOKEN) on every
request, which meant a captured request leaked the shared secret permanently
and could be replayed indefinitely. This module replaces it with a
signed-request scheme:

    canonical = METHOD \\n PATH \\n TIMESTAMP \\n NONCE \\n SHA256(body)
    signature = HMAC-SHA256(secret, canonical).hexdigest()

Headers sent by the sensor:

    X-IDS-Timestamp   Unix seconds
    X-IDS-Nonce       16-byte hex, unique per request
    X-IDS-Signature   HMAC-SHA256 hex digest

Properties:
    - The shared secret is never transmitted; a captured request leaks nothing
    - Replay protection via nonce + timestamp window
    - Body tamper detection via SHA256(body) inside the signed payload
    - Constant-time comparison on the server side

Limitations:
    - Nonce store is in-process. With multiple gunicorn workers, a replay
      within the skew window would have to hit the same worker to be caught.
      The current single-process Flask server does not have this problem.
      Move the nonce store to Redis or MySQL before scaling to multiple
      workers.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time


MAX_CLOCK_SKEW_SEC = int(os.getenv("IDS_AUTH_MAX_SKEW_SEC", "60") or "60")
NONCE_RETENTION_SEC = int(os.getenv("IDS_AUTH_NONCE_RETENTION_SEC", "300") or "300")

TIMESTAMP_HEADER = "X-IDS-Timestamp"
NONCE_HEADER = "X-IDS-Nonce"
SIGNATURE_HEADER = "X-IDS-Signature"


def _canonical(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body or b"").hexdigest()
    payload = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_hash}"
    return payload.encode("utf-8")


def sign_request(
    secret: str,
    method: str,
    path: str,
    body: bytes,
    *,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """
    Return the three signing headers for one request.

    method / path / body must be exactly what the HTTP client will send.
    In particular, use the raw body bytes that will appear on the wire —
    do not let the HTTP library re-serialize a dict, because key ordering
    and separator differences would invalidate the signature.
    """
    ts = str(timestamp if timestamp is not None else int(time.time()))
    nc = nonce or secrets.token_hex(16)
    canonical = _canonical(method, path, ts, nc, body)
    sig = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return {
        TIMESTAMP_HEADER: ts,
        NONCE_HEADER: nc,
        SIGNATURE_HEADER: sig,
    }


class NonceTracker:
    """Thread-safe, in-memory record of recently-seen nonces."""

    def __init__(self, retention_sec: int = NONCE_RETENTION_SEC) -> None:
        self._retention = retention_sec
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self._last_sweep = 0.0

    def check_and_record(self, nonce: str) -> bool:
        """Return True if the nonce is fresh, False if already seen."""
        now = time.time()
        with self._lock:
            # Amortized sweep: at most once per second.
            if now - self._last_sweep > 1.0:
                cutoff = now - self._retention
                stale = [n for n, exp in self._seen.items() if exp < cutoff]
                for n in stale:
                    self._seen.pop(n, None)
                self._last_sweep = now

            if nonce in self._seen:
                return False
            self._seen[nonce] = now + self._retention
            return True


def verify_request(
    secret: str,
    method: str,
    path: str,
    body: bytes,
    headers: dict[str, str],
    nonce_tracker: NonceTracker,
    *,
    now: float | None = None,
) -> tuple[bool, str]:
    """
    Verify a signed request. Returns (ok, reason). reason is a short
    diagnostic string on failure, empty on success.
    """
    ts = headers.get(TIMESTAMP_HEADER, "")
    nc = headers.get(NONCE_HEADER, "")
    sig = headers.get(SIGNATURE_HEADER, "")

    if not ts or not nc or not sig:
        return False, "missing_signing_headers"

    try:
        ts_int = int(ts)
    except ValueError:
        return False, "invalid_timestamp"

    now_ts = now if now is not None else time.time()
    if abs(now_ts - ts_int) > MAX_CLOCK_SKEW_SEC:
        return False, "timestamp_out_of_window"

    expected = hmac.new(
        secret.encode("utf-8"),
        _canonical(method, path, ts, nc, body),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, sig):
        return False, "bad_signature"

    if not nonce_tracker.check_and_record(nc):
        return False, "replayed_nonce"

    return True, ""