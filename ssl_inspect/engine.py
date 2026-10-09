"""
Standalone TLS interceptor process.

Spawns mitmproxy in transparent mode with the IDS addon. Started by the
process supervisor as a separate OS process (not a thread) so an
interceptor crash cannot take down the web UI or the Scapy sensor.

The package is named ssl_inspect (not ssl) to avoid shadowing the Python
standard library ssl module, which requests, urllib3, and mitmproxy all
depend on.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

from logging_config import get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
CONF_DIR = REPO_ROOT / "ssl_inspect" / "mitm-conf"
ADDON_PATH = REPO_ROOT / "ssl_inspect" / "interceptor.py"

LISTEN_PORT = int(os.getenv("SSL_INTERCEPT_PORT", "8443") or "8443")
LISTEN_HOST = os.getenv("SSL_INTERCEPT_HOST", "0.0.0.0")


def build_command() -> list[str]:
    """
    Build the mitmdump argv. Uses `python -m mitmproxy.tools.dump`
    instead of the `mitmdump` console script so we always run in the
    same interpreter that has the IDS dependencies installed.
    """
    return [
        sys.executable, "-m", "mitmproxy.tools.dump",
        "--mode", "transparent",
        "--listen-host", LISTEN_HOST,
        "--listen-port", str(LISTEN_PORT),
        "--set", f"confdir={CONF_DIR}",
        "--set", "ssl_insecure=true",       # don't verify upstream certs (NGFW parity)
        "--set", "termlog_verbosity=warn",
        "-s", str(ADDON_PATH),
        "--quiet",
    ]


def run_forever() -> int:
    # Fail fast with a clear message if the SSL extra isn't installed,
    # rather than spawning mitmdump and letting it die with a subprocess
    # traceback that buries the actual cause.
    try:
        import mitmproxy  # noqa: F401
    except ImportError:
        logger.error(
            "mitmproxy is not installed. Install the SSL extra with "
            "`pip install -e \".[ssl]\"` before starting the interceptor."
        )
        return 1

    CONF_DIR.mkdir(parents=True, exist_ok=True)

    from ssl_inspect.ca import ensure_ca
    ensure_ca()

    # Ensure the repo root is on PYTHONPATH so mitmproxy's addon loader
    # can resolve `from storage import ...` inside interceptor.py.
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{existing}" if existing else str(REPO_ROOT)

    cmd = build_command()
    logger.info("Starting SSL interceptor: %s", " ".join(cmd))

    proc = subprocess.Popen(cmd, cwd=str(REPO_ROOT), env=env)

    def _handler(signum, frame):
        logger.info("SSL interceptor received signal %s, terminating child", signum)
        proc.terminate()

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)

    try:
        return proc.wait()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=3)


if __name__ == "__main__":
    import dotenv
    dotenv.load_dotenv()
    raise SystemExit(run_forever())