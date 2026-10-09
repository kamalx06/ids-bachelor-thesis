"""Bypass rules: which SNI / IPs skip TLS interception."""

from __future__ import annotations

import fnmatch
import ipaddress
import threading
import time

from sqlalchemy import select

from logging_config import get_logger
from storage.db import get_session
from storage.models import SslBypassRule

logger = get_logger(__name__)

_REFRESH_INTERVAL = 30.0
_lock = threading.Lock()
_rules: list[dict] = []
_last_refresh: float = 0.0


def _load_rules() -> list[dict]:
    session = get_session()
    try:
        rows = session.execute(
            select(
                SslBypassRule.match_type,
                SslBypassRule.pattern,
                SslBypassRule.reason,
            ).where(SslBypassRule.enabled.is_(True))
        ).all()
        return [
            {"match_type": mt, "pattern": pat, "reason": rsn}
            for mt, pat, rsn in rows
        ]
    except Exception:
        logger.error("Failed to load SSL bypass rules", exc_info=True)
        return []
    finally:
        session.close()


def refresh(force: bool = False) -> None:
    global _rules, _last_refresh
    now = time.time()
    with _lock:
        if not force and now - _last_refresh < _REFRESH_INTERVAL:
            return
        _rules = _load_rules()
        _last_refresh = now


def should_bypass_sni(sni: str | None) -> bool:
    if not sni:
        return False
    refresh()
    sni_l = sni.lower()
    with _lock:
        for rule in _rules:
            if rule["match_type"] != "sni":
                continue
            if fnmatch.fnmatchcase(sni_l, rule["pattern"].lower()):
                return True
    return False


def should_bypass_ip(ip: str | None) -> bool:
    if not ip:
        return False
    refresh()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    with _lock:
        for rule in _rules:
            mt = rule["match_type"]
            if mt == "ip" and rule["pattern"] == ip:
                return True
            if mt == "cidr":
                try:
                    if addr in ipaddress.ip_network(rule["pattern"], strict=False):
                        return True
                except ValueError:
                    continue
    return False