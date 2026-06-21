import os
import time
import warnings
from urllib.parse import urlparse

import dotenv
import requests
import urllib3
from storage.persistence import get_live_stats

from logging_config import get_logger

dotenv.load_dotenv()

API_URL = os.environ.get("API_URL")
SEND_INTERVAL = float(os.environ.get("SEND_INTERVAL", "5") or "5")
STARTUP_DELAY = float(os.environ.get("SENDER_STARTUP_DELAY", "8") or "8")
SENDER_MAX_WAIT = float(os.environ.get("SENDER_MAX_WAIT", "45") or "45")
IDS_SENSOR_TOKEN = os.environ.get("IDS_SENSOR_TOKEN", "")

logger = get_logger(__name__)

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


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


def _request_headers() -> dict:
    headers = {}
    if IDS_SENSOR_TOKEN:
        headers["X-IDS-TOKEN"] = IDS_SENSOR_TOKEN
    return headers


def _post_telemetry() -> requests.Response:
    return requests.post(
        f"{_SAFE_API_URL}/update",
        json=_build_payload(),
        headers=_request_headers(),
        timeout=5,
        verify=_TLS_VERIFY,
    )


def _wait_for_web_ui() -> bool:
    if not _SAFE_API_URL:
        return False

    if STARTUP_DELAY > 0:
        logger.info("Telemetry sender waiting %.1fs for Web UI to start", STARTUP_DELAY)
        time.sleep(STARTUP_DELAY)

    deadline = time.time() + max(SENDER_MAX_WAIT, STARTUP_DELAY)
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            response = _post_telemetry()
            if response.status_code in (200, 401):
                if response.status_code == 401:
                    logger.error(
                        "Web UI rejected telemetry (401). Check IDS_SENSOR_TOKEN matches on server."
                    )
                    return False
                logger.info("Web UI telemetry connected (%s)", _SAFE_API_URL)
                return True
            logger.debug("Web UI returned HTTP %s while waiting", response.status_code)
        except requests.exceptions.SSLError as exc:
            logger.warning(
                "TLS error talking to %s — set IDS_TLS_VERIFY=false for local adhoc HTTPS: %s",
                _SAFE_API_URL,
                exc,
            )
        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            logger.debug("Web UI not ready yet", exc_info=True)

        time.sleep(min(2.0, max(0.5, deadline - time.time())))

    logger.warning(
        "Web UI not reachable at %s/update after %.0fs (%d attempts). "
        "Ensure uni-srver.py is running and API_URL uses https://127.0.0.1:5000/ids when WEB_UI_SSL=true.",
        _SAFE_API_URL,
        SENDER_MAX_WAIT,
        attempt,
    )
    return False


def start_sender():
    _wait_for_web_ui()

    consecutive_failures = 0

    while True:
        try:
            if not _SAFE_API_URL:
                time.sleep(SEND_INTERVAL)
                continue

            response = _post_telemetry()
            response.raise_for_status()
            consecutive_failures = 0

        except requests.exceptions.SSLError as exc:
            consecutive_failures += 1
            if consecutive_failures <= 3 or consecutive_failures % 12 == 0:
                logger.warning(
                    "TLS verification failed for %s/update: %s. "
                    "For local dev with adhoc HTTPS, set IDS_TLS_VERIFY=false in .env",
                    _SAFE_API_URL,
                    exc,
                )
        except requests.exceptions.ConnectionError:
            consecutive_failures += 1
            if consecutive_failures <= 3 or consecutive_failures % 12 == 0:
                logger.warning(
                    "Web UI telemetry unreachable at %s/update (%d failures). "
                    "Is uni-srver.py running and API_URL correct?",
                    _SAFE_API_URL,
                    consecutive_failures,
                )
        except requests.exceptions.HTTPError as exc:
            consecutive_failures += 1
            logger.warning(
                "Telemetry POST failed: HTTP %s",
                getattr(exc.response, "status_code", "?"),
            )
        except Exception:
            consecutive_failures += 1
            logger.error("Sender error while posting telemetry", exc_info=True)

        time.sleep(SEND_INTERVAL)
