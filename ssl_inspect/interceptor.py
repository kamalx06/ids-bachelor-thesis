"""
mitmproxy addon. Decrypted HTTP flows are converted into packet-shaped
dicts and fed through the SAME analyze_packet() + persistence pipeline
that the Scapy sensor uses. The only difference: no flow-level features,
so the ML step is skipped (features=None).
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

# mitmproxy loads this file with its own sys.path; make the repo root
# importable so `from storage import ...` resolves.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from mitmproxy import http, tls  # noqa: E402

from logging_config import get_logger  # noqa: E402
from ids.ai_analysis import analyze_packet  # noqa: E402
from storage import persistence  # noqa: E402
from ssl_inspect import bypass  # noqa: E402

logger = get_logger(__name__)


class IDSInterceptor:
    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._writer_started = False
        self._lock = threading.Lock()
        self._decrypted = 0
        self._bypassed = 0
        self._failures = 0

    # ------------------------------------------------------------------
    # mitmproxy lifecycle hooks
    # ------------------------------------------------------------------

    def running(self) -> None:
        with self._lock:
            if self._writer_started:
                return
            try:
                persistence.init_persistence()
            except Exception:
                logger.error("SSL interceptor: persistence init failed", exc_info=True)
            threading.Thread(
                target=persistence.writer_loop,
                args=(self._stop_event,),
                daemon=True,
                name="ssl-persistence-writer",
            ).start()
            self._writer_started = True
            logger.info("SSL interceptor: ready (persistence writer started)")

    def done(self) -> None:
        self._stop_event.set()
        logger.info(
            "SSL interceptor stopping: decrypted=%d bypassed=%d failures=%d",
            self._decrypted, self._bypassed, self._failures,
        )

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """
        Decide whether to skip interception for this connection.

        Two match types are honored: SNI glob patterns and client IP /
        CIDR rules. The IP check reads the peer address from the
        connection context; if it is unavailable (rare, but possible
        with certain upstream proxies), only SNI matching applies.
        """
        sni = (data.client_hello.sni or "").lower()

        client_ip: str | None = None
        try:
            peername = data.context.client.peername
            if peername:
                client_ip = peername[0]
        except Exception:
            client_ip = None

        if bypass.should_bypass_sni(sni) or bypass.should_bypass_ip(client_ip):
            data.ignore_connection = True
            self._bypassed += 1
            logger.debug("SSL bypass: sni=%s client_ip=%s", sni, client_ip or "-")

    # ------------------------------------------------------------------
    # Flow emission
    # ------------------------------------------------------------------

    def response(self, flow: http.HTTPFlow) -> None:
        """Called once per HTTP response. Emit for analysis."""
        try:
            self._emit(flow)
            self._decrypted += 1
        except Exception:
            self._failures += 1
            logger.error("SSL interceptor: emit failed", exc_info=True)

    def _emit(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        resp = flow.response
        if req is None:
            return

        body = ""
        if req.content:
            try:
                body = req.content.decode("utf-8", errors="ignore")[:8192]
            except Exception:
                body = ""

        client = flow.client_conn.peername or ("", 0)
        server = flow.server_conn.peername or ("", 0)
        src_ip, src_port = client
        dst_ip, dst_port = server

        # Skip private-to-private (inter-IDS chatter)
        if not src_ip or not dst_ip:
            return

        data = {
            "src_ip": str(src_ip),
            "dst_ip": str(dst_ip),
            "src_port": int(src_port or 0),
            "dst_port": int(dst_port or 0),
            "protocol": "TCP",
            "url": req.pretty_url,
            "http": {
                "method": req.method,
                "host": req.host,
                "path": req.path,
                "url": req.pretty_url,
                "headers": dict(req.headers),
                "query": dict(req.query),
                "body": body,
                "status_code": resp.status_code if resp else None,
            },
            "features": None,       # ← no flow-level features from mitmproxy
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
            "src_ip": data["src_ip"],
            "dst_ip": data["dst_ip"],
            "src_port": data["src_port"],
            "dst_port": data["dst_port"],
            "protocol": "TCP",
            "url": data["url"],
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

        # Training samples are valuable for retraining, and SSL-decrypted
        # payloads add attack diversity the Scapy path won't see.
        # But because features=None, we skip the training sample — the
        # retrainer expects a full feature vector. See Limitations.


addons = [IDSInterceptor()]