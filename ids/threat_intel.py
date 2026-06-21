"""
Threat intelligence enrichment with MySQL cache and pressure-aware skipping.
"""

from __future__ import annotations

import os

from intelligence.reputation import check_blocklist, check_ip, check_url, is_private_ip, lookup_ip, lookup_url
from logging_config import get_logger
from storage.persistence import get_ti_cache, set_ti_cache

logger = get_logger(__name__)

_TI_MIN_SCORE = float(os.getenv("TI_MIN_SCORE_FOR_LOOKUP", "0.25") or "0.25")
_TI_FULL_ENRICH = float(os.getenv("TI_FULL_ENRICH_SCORE", "0.45") or "0.45")
_ZEEK_ENABLED = (os.getenv("IDS_ZEEK_ENABLED", "false") or "false").lower() == "true"


def _zeek_available() -> bool:
    if not _ZEEK_ENABLED:
        return False
    try:
        from intelligence.zeek_integration import zeek_logs_available

        return zeek_logs_available()
    except Exception:
        return False


def enrich(
    data: dict,
    *,
    ai_score: float,
    behavior: str | None,
    queue_pressure: float,
    skip_heavy: bool = False,
    model_trusted: bool = True,
) -> tuple[dict | None, dict | None, dict | None, list[str]]:
    reasons: list[str] = []
    ti_ip = None
    ti_url = None
    zeek_data = None

    src_ip = data.get("src_ip")
    if src_ip and not is_private_ip(src_ip):
        block = check_blocklist(src_ip)
        if block:
            ti_ip = block
            reasons.append("reputation_ip_malicious")

    threshold = _TI_MIN_SCORE
    if not model_trusted:
        threshold = max(threshold, 0.40)
    if queue_pressure > 0.5:
        threshold = max(threshold, 0.50)
    if skip_heavy or queue_pressure > 0.75:
        return ti_ip, None, None, reasons

    # Run full TI when ML/behavior already elevated, or for obvious scan/flood
    if ai_score < threshold and behavior not in ("port_scan", "flood") and not ti_ip:
        return None, None, None, reasons

    if src_ip and not ti_ip:
        cached = get_ti_cache(src_ip, "ip")
        if cached:
            ti_ip = cached
        else:
            try:
                ti_ip = lookup_ip(src_ip)
                if ti_ip:
                    set_ti_cache(src_ip, "ip", ti_ip)
            except Exception:
                logger.debug("TI IP lookup failed for %s", src_ip, exc_info=True)

        rep = (ti_ip.get("verdict") if ti_ip else check_ip(src_ip))
        if rep and rep != "unknown":
            reasons.append(f"reputation_ip_{rep}")

    url = data.get("url")
    if url and (ai_score >= _TI_FULL_ENRICH or (ti_ip and ti_ip.get("verdict") in {"suspicious", "malicious"})):
        cached = get_ti_cache(url, "url")
        if cached:
            ti_url = cached
        else:
            try:
                ti_url = lookup_url(url)
                if ti_url:
                    set_ti_cache(url, "url", ti_url)
            except Exception:
                logger.debug("TI URL lookup failed", exc_info=True)

        rep_url = (ti_url.get("verdict") if ti_url else check_url(url))
        if rep_url and rep_url != "unknown":
            reasons.append(f"reputation_url_{rep_url}")

    if _zeek_available() and not skip_heavy and queue_pressure <= 0.75:
        src_ip = data.get("src_ip")
        if src_ip and not is_private_ip(src_ip):
            try:
                from intelligence.zeek_integration import lookup_ip as zeek_lookup

                zeek_data = zeek_lookup(src_ip)
                if zeek_data.get("reason"):
                    reasons.append(zeek_data["reason"])
                for sig in zeek_data.get("signals") or []:
                    if sig not in reasons:
                        reasons.append(sig)
            except Exception:
                zeek_data = None

    return ti_ip, ti_url, zeek_data, reasons
