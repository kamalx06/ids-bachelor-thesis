"""
Fast Scapy capture path: extract features and enqueue lightweight dicts only.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable

from scapy.all import Raw

from engine.feature_extractor import extract
from engine.parser_http import parse_http
from ids.event_timestamp import resolve_event_epoch_seconds, scapy_packet_epoch_seconds
from logging_config import get_logger

logger = get_logger(__name__)

try:
    from scapy.layers.dns import DNS, DNSQR
except Exception:
    DNS = None
    DNSQR = None

_URL_REGEX = re.compile(rb"(?:GET|POST)\s+([^\s]+)")


def extract_http_url(pkt) -> str | None:
    if not pkt.haslayer(Raw):
        return None
    data = pkt[Raw].load
    match = _URL_REGEX.search(data)
    if match:
        return match.group(1).decode(errors="ignore")
    return None


def extract_dns_event(pkt) -> dict | None:
    if DNS is None or not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
        return None
    try:
        dns_layer = pkt[DNS]
        if int(getattr(dns_layer, "qr", 0)) != 0:
            return None
        if int(getattr(dns_layer, "qdcount", 0) or 0) <= 0:
            return None
        q = pkt[DNSQR]
        qname = (
            q.qname.decode(errors="ignore")
            if isinstance(q.qname, (bytes, bytearray))
            else str(q.qname)
        )
        return {
            "qname": qname,
            "qtype": getattr(q, "qtype", None),
            "qdcount": int(getattr(dns_layer, "qdcount", 0) or 0),
        }
    except Exception:
        return None


def preprocess_packet(pkt) -> dict | None:
    """Extract features and metadata from a captured Scapy packet."""
    data = extract(pkt)
    if not data:
        return None

    wire = data.get("packet_send_time") or scapy_packet_epoch_seconds(pkt)
    resolved_ts = resolve_event_epoch_seconds(
        packet_send_time=wire,
        fallback_ingestion_time=time.time(),
    )

    http_data = parse_http(pkt)
    url = None
    if http_data:
        url = http_data.get("url") or (
            f"http://{http_data['host']}{http_data.get('path', '')}"
            if http_data.get("host")
            else http_data.get("path")
        )
    if not url:
        url = extract_http_url(pkt)

    return {
        "data": data,
        "packet_send_time": wire,
        "captured_at": resolved_ts,
        "url": url,
        "http": http_data,
        "dns_event": extract_dns_event(pkt),
    }


def make_capture_callback(
    *,
    on_captured: Callable[[], None],
    enqueue: Callable[[dict], bool],
    enqueue_raw: Callable[[Any], bool] | None = None,
    should_sample: Callable[[], bool],
) -> Callable:
    """Build Scapy prn callback."""

    def capture_callback(pkt) -> None:
        if should_sample():
            return

        on_captured()

        if enqueue_raw is not None:
            try:
                pkt_copy = pkt.copy()
            except Exception:
                pkt_copy = pkt
            if not enqueue_raw(pkt_copy):
                logger.debug("Packet dropped at raw enqueue")
            return

        item = preprocess_packet(pkt)
        if item is None:
            return
        if not enqueue(item):
            logger.debug("Packet dropped at enqueue")

    return capture_callback
