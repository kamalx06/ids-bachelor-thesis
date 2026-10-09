"""
IDS sensor → web UI telemetry sender.

Runs as a background thread inside ids_engine.py. Every SEND_INTERVAL
seconds, it POSTs the current live counters to the Web UI's /ids/update
endpoint, authenticated with an HMAC-signed request (see
intelligence/sensor_auth.py for the wire format).

Design notes:
    - Signed, not bearer. The shared secret (IDS_SENSOR_TOKEN) is used as
      an HMAC key and never transmitted. Replay is prevented by a nonce +
      timestamp window; tampering is prevented by including SHA256(body)
      in the signed payload.
    - The body bytes are serialized explicitly so the exact bytes that go
      on the wire are the bytes that were signed. requests' json= kwarg
      can re-serialize with different key order or separators.
    - Exponential backoff on sustained outage: at most
      _MAX_BACKOFF_MULTIPLIER × SEND_INTERVAL between retries. Recovery
      from a transient failure is immediate; recovery from a long outage
      does not hammer the server.
    - The startup wait loop tolerates the Web UI being slower to start
      than the sensor (common under the supervisor, which starts both
      in parallel).
"""

from __future__ import annotations

import json
import os
import time
import warnings
from urllib.parse import urlparse

import dotenv
import requests
import urllib3

from intelligence.sensor_auth import sign_request
from logging_config import get_logger
from storage.persistence import get_live_stats

dotenv.load_dotenv()

API_URL = os.environ.get("API_URL")
SEND_INTERVAL = float(os.environ.get("SEND_INTERVAL", "5") or "5")
STARTUP_DELAY = float(os.environ.get("SENDER_STARTUP_DELAY", "8") or "8")
SENDER_MAX_WAIT = float(os.environ.get("SENDER_MAX_WAIT", "45") or "45")
IDS_SENSOR_TOKEN = os.environ.get("IDS_SENSOR_TOKEN", "")

logger = get_logger(__name__)

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


# ---------------------------------------------------------------------------
# URL / TLS validation
# ---------------------------------------------------------------------------

def _validate_api_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise RuntimeError("API_URL must start with http:// or https://")
    if parsed.scheme == "http" and parsed.hostname not in _LOCAL_HOSTS:
        raise RuntimeError("API_URL must use HTTPS for non-local hosts")
    return url.rstrip("/")


def _tls_verify(url: str) -> bool:
    """Self-signed Flask (ssl_context='adhoc') needs verify=False on localhost."""
    explicit = (os.environ.get("IDS_TLS_VERIFY") or "").strip().lower()
    if explicit in ("true", "1", "yes"):
        return True
    if explicit in ("false", "0", "no"):
        return False
    parsed = urlparse(url)
    return not (parsed.scheme == "https" and parsed.hostname in _LOCAL_HOSTS)


_SAFE_API_URL = _validate_api_url(API_URL)
_TLS_VERIFY = _tls_verify(_SAFE_API_URL) if _SAFE_API_URL else True

if _SAFE_API_URL and not _TLS_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------

def _build_payload() -> dict:
    live = get_live_stats()
    return {
        "stats": {
            "total": int(live["total"]),
            "safe": int(live["safe"]),
            "suspicious": int(live["suspicious"]),
            "dangerous": int(live["dangerous"]),
            "unique_attackers": list(live["unique_attackers"]),
            "dangerous_ips": list(live["dangerous_ips"]),
            "dangerous_urls": list(live["dangerous_urls"]),
        },
    }


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------

def _post_telemetry() -> requests.Response:
    """
    Send one signed telemetry POST.

    The body is serialized here and passed to requests as raw bytes so the
    exact byte sequence that goes on the wire is the one that gets signed.
    Using requests' json= kwarg would let it re-serialize the dict and
    invalidate the signature.
    """
    url = f"{_SAFE_API_URL}/update"
    path = urlparse(url).path or "/ids/update"
    body = json.dumps(_build_payload(), separators=(",", ":")).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    if IDS_SENSOR_TOKEN:
        headers.update(sign_request(IDS_SENSOR_TOKEN, "POST", path, body))

    return requests.post(
        url,
        data=body,
        headers=headers,
        timeout=5,
        verify=_TLS_VERIFY,
    )


# ---------------------------------------------------------------------------
# Startup wait
# ---------------------------------------------------------------------------

def _wait_for_web_ui() -> bool:
    if not _SAFE_API_URL:
        logger.warning("API_URL is not set; telemetry will not be sent.")
        return False

    if not IDS_SENSOR_TOKEN:
        logger.error(
            "IDS_SENSOR_TOKEN is not set. Telemetry will be sent unsigned and "
            "rejected by the Web UI. Set IDS_SENSOR_TOKEN in .env on both sides."
        )

    if STARTUP_DELAY > 0:
        logger.info("Telemetry sender waiting %.1fs for Web UI to start", STARTUP_DELAY)
        time.sleep(STARTUP_DELAY)

    deadline = time.time() + max(SENDER_MAX_WAIT, STARTUP_DELAY)
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            response = _post_telemetry()
            if response.status_code == 200:
                logger.info("Web UI telemetry connected (%s)", _SAFE_API_URL)
                return True
            if response.status_code in (401, 403):
                logger.error(
                    "Web UI rejected telemetry (HTTP %s). Verify IDS_SENSOR_TOKEN "
                    "matches on both sides, and that the two hosts' clocks agree "
                    "within %ss.",
                    response.status_code,
                    os.getenv("IDS_AUTH_MAX_SKEW_SEC", "60"),
                )
                return False
            logger.debug("Web UI returned HTTP %s while waiting", response.status_code)
        except requests.exceptions.SSLError as exc:
            logger.warning(
                "TLS error talking to %s — set IDS_TLS_VERIFY=false for local adhoc HTTPS: %s",
                _SAFE_API_URL, exc,
            )
        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            logger.debug("Web UI not ready yet", exc_info=True)

        time.sleep(min(2.0, max(0.5, deadline - time.time())))

    logger.warning(
        "Web UI not reachable at %s/update after %.0fs (%d attempts). "
        "Ensure uni-srver.py is running and API_URL uses https://127.0.0.1:5000/ids "
        "when WEB_UI_SSL=true.",
        _SAFE_API_URL, SENDER_MAX_WAIT, attempt,
    )
    return False


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

# Backoff cap: at most this many multiples of SEND_INTERVAL between retries
# during a sustained outage. Keeps recovery quick but stops hammering.
_MAX_BACKOFF_MULTIPLIER = 12


def _classify_http_error(response: requests.Response) -> str | None:
    """
    Return a human-readable reason for a non-2xx response, or None if the
    response body cannot be parsed. The server sends
    {"success": false, "error": {"code": "...", "message": "..."}} for
    every rejection.
    """
    try:
        payload = response.json()
    except Exception:
        return None
    err = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(err, dict):
        code = err.get("code") or ""
        message = err.get("message") or ""
        if code and message:
            return f"{code}: {message}"
        return code or message or None
    if isinstance(err, str):
        return err
    return None


def start_sender() -> None:
    _wait_for_web_ui()

    consecutive_failures = 0
    last_logged_reason: str | None = None

    while True:
        sleep_for = SEND_INTERVAL

        try:
            if not _SAFE_API_URL:
                time.sleep(SEND_INTERVAL)
                continue

            response = _post_telemetry()

            if 200 <= response.status_code < 300:
                if consecutive_failures > 0:
                    logger.info(
                        "Telemetry recovered after %d consecutive failure(s)",
                        consecutive_failures,
                    )
                consecutive_failures = 0
                last_logged_reason = None

            else:
                consecutive_failures += 1
                reason = _classify_http_error(response) or f"HTTP {response.status_code}"

                # Only log the first few and then every 12th; below that, a
                # persistent misconfiguration would flood the log.
                should_log = (
                    consecutive_failures <= 3
                    or consecutive_failures % 12 == 0
                    or reason != last_logged_reason
                )
                if should_log:
                    if response.status_code in (401, 403):
                        logger.error(
                            "Telemetry rejected: %s (consecutive_failures=%d). "
                            "Check that IDS_SENSOR_TOKEN matches on both sides and "
                            "that the two clocks are within the skew window.",
                            reason, consecutive_failures,
                        )
                    else:
                        logger.warning(
                            "Telemetry POST failed: %s (consecutive_failures=%d)",
                            reason, consecutive_failures,
                        )
                last_logged_reason = reason

        except requests.exceptions.SSLError as exc:
            consecutive_failures += 1
            if consecutive_failures <= 3 or consecutive_failures % 12 == 0:
                logger.warning(
                    "TLS verification failed for %s/update: %s. "
                    "For local dev with adhoc HTTPS, set IDS_TLS_VERIFY=false in .env",
                    _SAFE_API_URL, exc,
                )
        except requests.exceptions.ConnectionError:
            consecutive_failures += 1
            if consecutive_failures <= 3 or consecutive_failures % 12 == 0:
                logger.warning(
                    "Web UI telemetry unreachable at %s/update (%d failures). "
                    "Is uni-srver.py running and API_URL correct?",
                    _SAFE_API_URL, consecutive_failures,
                )
        except requests.exceptions.Timeout:
            consecutive_failures += 1
            if consecutive_failures <= 3 or consecutive_failures % 12 == 0:
                logger.warning(
                    "Telemetry POST timed out (%d consecutive failures)",
                    consecutive_failures,
                )
        except Exception:
            consecutive_failures += 1
            logger.error("Sender error while posting telemetry", exc_info=True)

        if consecutive_failures > 0:
            sleep_for = SEND_INTERVAL * min(
                consecutive_failures, _MAX_BACKOFF_MULTIPLIER
            )
        time.sleep(sleep_for)