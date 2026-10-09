"""
Standalone TLS interceptor process.

Spawns sslsplit in transparent mode with the IDS's root CA. Started by
the process supervisor as a separate OS process, so an interceptor crash
cannot take down the web UI or the Scapy sensor.

A background thread (sslsplit_reader) tails the connect log written by
sslsplit and feeds decrypted HTTP flows into the same analyze_packet()
pipeline the Scapy sensor uses.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from logging_config import get_logger

logger = get_logger(__name__)

REPO_ROOT = _REPO_ROOT
CONF_DIR = REPO_ROOT / "ssl_inspect" / "conf"
CA_CERT = CONF_DIR / "sslsplit-ca.crt"
CA_KEY = CONF_DIR / "sslsplit-ca.key"

STORAGE_DIR = REPO_ROOT / "storage"
CONNECT_LOG = STORAGE_DIR / "sslsplit-connect.log"
CONTENT_DIR = STORAGE_DIR / "sslsplit-content"

LISTEN_PORT = int(os.getenv("SSL_INTERCEPT_PORT", "8443") or "8443")
LISTEN_HOST = os.getenv("SSL_INTERCEPT_HOST", "0.0.0.0")


def _sslsplit_binary() -> str | None:
    """Return the sslsplit executable path, or None if not on PATH."""
    return shutil.which("sslsplit")


def _ensure_ca_files() -> bool:
    """Regenerate the split cert/key if they do not exist yet."""
    if CA_CERT.is_file() and CA_KEY.is_file():
        return True

    from ssl_inspect.ca import export_for_sslsplit
    try:
        export_for_sslsplit()
    except Exception:
        logger.error("Failed to export the root CA for sslsplit", exc_info=True)
        return False
    return CA_CERT.is_file() and CA_KEY.is_file()


def build_command() -> list[str]:
    """
    Build the sslsplit argv. Transparent mode, one connection log that the
    reader thread tails, and per-connection content logs for forensic
    retention.

        sslsplit -D -l <connect.log> -S <content_dir> -k <ca.key> -c <ca.crt> \\
                 ssl <host> <port>
    """
    return [
        "sslsplit",
        "-D",                                   # run in foreground (no daemonize)
        "-l", str(CONNECT_LOG),                 # one line per connection
        "-S", str(CONTENT_DIR),                 # per-connection content log
        "-k", str(CA_KEY),
        "-c", str(CA_CERT),
        "ssl", LISTEN_HOST, str(LISTEN_PORT),
    ]


_IPTABLES_SYNC_INTERVAL = float(os.getenv("SSL_BYPASS_SYNC_SEC", "30") or "30")


def _iptables_sync_loop(stop_event) -> None:
    """
    Periodically reconcile the iptables SNI bypass rules with the
    database. The interceptor runs as root (spawned by the supervisor,
    which itself runs as root), so it can perform the reconciliation.

    Runs forever until stop_event is set.
    """
    from ssl_inspect import bypass

    logger.info(
        "iptables bypass sync loop started (interval=%.0fs)",
        _IPTABLES_SYNC_INTERVAL,
    )
    # First pass runs immediately so the firewall is correct at startup.
    while not stop_event.is_set():
        try:
            summary = bypass.sync_iptables()
            if not summary.get("root"):
                logger.warning(
                    "iptables bypass sync skipped: not running as root. "
                    "SNI bypass rules will not be enforced."
                )
                # No point retrying every 30 s if we can never succeed.
                return
        except Exception:
            logger.error("iptables bypass sync failed", exc_info=True)
        stop_event.wait(_IPTABLES_SYNC_INTERVAL)


def run_forever() -> int:
    binary = _sslsplit_binary()
    if binary is None:
        logger.error(
            "sslsplit is not installed. Install it with "
            "`sudo dnf install sslsplit` before starting the interceptor."
        )
        return 1

    CONF_DIR.mkdir(parents=True, exist_ok=True)
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    CONTENT_DIR.mkdir(parents=True, exist_ok=True)

    if not _ensure_ca_files():
        return 1

    # Truncate the connect log so the reader starts from a clean state.
    try:
        CONNECT_LOG.write_text("", encoding="utf-8")
    except OSError:
        logger.warning(
            "Could not truncate %s; the reader will skip to end of file",
            CONNECT_LOG,
        )

    # Start the reader thread BEFORE spawning sslsplit so it can pick up
    # lines as soon as sslsplit begins writing.
    from ssl_inspect.sslsplit_reader import SslsplitReader
    reader = SslsplitReader(CONNECT_LOG)
    reader.start()

    # Start the iptables sync thread. It runs as root because the
    # supervisor runs as root, so it can reconcile the SNI bypass
    # rules with the database independently of the web UI.
    import threading as _threading
    _sync_stop = _threading.Event()
    _sync_thread = _threading.Thread(
        target=_iptables_sync_loop,
        args=(_sync_stop,),
        daemon=True,
        name="bypass-iptables-sync",
    )
    _sync_thread.start()

    cmd = build_command()
    logger.info("Starting TLS interceptor: %s", " ".join(cmd))

    proc = subprocess.Popen(cmd, cwd=str(REPO_ROOT))

    def _handler(signum, frame):
        logger.info("TLS interceptor received signal %s, terminating child", signum)
        reader.stop()
        _sync_stop.set()
        proc.terminate()

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)

    try:
        return proc.wait()
    finally:
        reader.stop()
        _sync_stop.set()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=3)


if __name__ == "__main__":
    import dotenv
    dotenv.load_dotenv()
    raise SystemExit(run_forever())