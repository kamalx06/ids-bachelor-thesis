"""
Tails the sslsplit connect log and feeds decrypted HTTP flows into the
IDS analysis pipeline.

Replaces the retired mitmproxy addon. The downstream integration is
identical: each reconstructed flow becomes a packet-shaped dict passed
to analyze_packet() with features=None, and the result is persisted
through the same enqueue_packet_log() path.

The connect log line format for sslsplit 0.5.x is:

    <timestamp> <pid> <proto> <src_ip>:<src_port> <dst_ip>:<dst_port> <sni> [<http_method> <http_path>]

Example:

    2026-10-09 21:34:56 137729 ssl 192.168.1.10:52431 142.250.185.78:443 www.google.com GET /
"""

from __future__ import annotations

import re
import sys
import threading
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from logging_config import get_logger
from ids.ai_analysis import analyze_packet
from storage import persistence

logger = get_logger(__name__)

_CONNECT_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+"
    r"(?P<pid>\d+)\s+"
    r"(?P<proto>ssl|https|tcp)\s+"
    r"(?P<src_ip>\S+):(?P<src_port>\d+)\s+"
    r"(?P<dst_ip>\S+):(?P<dst_port>\d+)\s+"
    r"(?P<sni>\S+)"
    r"(?:\s+(?P<http_method>[A-Z]{3,8})\s+(?P<http_path>\S+))?"
    r"\s*$"
)


class SslsplitReader:
    """Watches the sslsplit connect log and emits analyzed events."""

    def __init__(self, connect_log: Path, poll_interval: float = 0.5) -> None:
        self._connect_log = connect_log
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._position = 0
        self._decrypted = 0
        self._skipped = 0
        self._failures = 0
        self._writer_started = False

    def stop(self) -> None:
        self._stop_event.set()

    def start(self) -> threading.Thread:
        t = threading.Thread(
            target=self._run,
            daemon=True,
            name="sslsplit-reader",
        )
        t.start()
        return t

    def _run(self) -> None:
        logger.info("sslsplit reader: watching %s", self._connect_log)

        try:
            persistence.init_persistence()
            threading.Thread(
                target=persistence.writer_loop,
                args=(self._stop_event,),
                daemon=True,
                name="sslsplit-persistence-writer",
            ).start()
            self._writer_started = True
        except Exception:
            logger.error("sslsplit reader: persistence init failed", exc_info=True)

        while not self._stop_event.is_set():
            try:
                self._process_new_lines()
            except Exception:
                logger.error("sslsplit reader iteration failed", exc_info=True)
            self._stop_event.wait(self._poll_interval)

    def _process_new_lines(self) -> None:
        if not self._connect_log.is_file():
            return

        with self._connect_log.open("r", encoding="utf-8", errors="replace") as f:
            try:
                current_size = self._connect_log.stat().st_size
            except OSError:
                return
            if current_size < self._position:
                logger.info("sslsplit connect log was truncated; resetting to start")
                self._position = 0

            f.seek(self._position)

            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                self._handle_line(line)

            self._position = f.tell()

    def _handle_line(self, line: str) -> None:
        match = _CONNECT_RE.match(line)
        if not match:
            self._skipped += 1
            if self._skipped <= 3:
                logger.debug(
                    "sslsplit reader: line did not match (sample %d): %s",
                    self._skipped, line[:160],
                )
            return

        try:
            self._emit_flow(match.groupdict())
            self._decrypted += 1
        except Exception:
            self._failures += 1
            logger.error("sslsplit reader: emit failed", exc_info=True)

    def _emit_flow(self, fields: dict) -> None:
        src_ip = fields["src_ip"]
        dst_ip = fields["dst_ip"]
        src_port = int(fields["src_port"])
        dst_port = int(fields["dst_port"])
        sni = fields.get("sni") or ""
        method = fields.get("http_method") or ""
        path = fields.get("http_path") or ""

        if not src_ip or not dst_ip:
            return

        if sni and path:
            url = f"https://{sni}{path}"
        elif sni:
            url = f"https://{sni}"
        else:
            url = ""

        data = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "TCP",
            "url": url,
            "http": {
                "method": method,
                "host": sni,
                "path": path,
                "url": url,
                "headers": {},
                "query": {},
                "body": "",
                "status_code": None,
            },
            "features": None,
            "decrypted": True,
            "packet_send_time": time.time(),
        }

        result = analyze_packet(
            data,
            dns_reasons=None,
            queue_pressure=0.0,
            skip_heavy_enrichment=False,
        )

        log_entry = {
            "time": time.time(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "TCP",
            "url": url,
            "http": data["http"],
            "status": result["classification"],
            "reasons": result["reasons"],
            "ai_label": result.get("ai_label"),
            "ai_score": result.get("ai_score"),
            "risk_score": result["risk_score"],
            "confidence": result.get("confidence"),
            "anomaly_score": result.get("anomaly_score"),
            "ti_ip": result.get("ti_ip"),
            "ti_url": result.get("ti_url"),
            "ai_explanation": result.get("explanation"),
        }
        persistence.enqueue_packet_log(log_entry)