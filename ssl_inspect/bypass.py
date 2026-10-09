"""
Bypass rules: which SNI / IPs skip TLS interception.

sslsplit has no SNI-level bypass hook, so SNI bypass is enforced at the
iptables layer. The mechanism:

    iptables -t nat PREROUTING inspects the first packet of each TCP
    connection. If that packet (the TLS ClientHello) contains one of the
    configured SNI byte sequences, the rule issues RETURN, and the whole
    flow bypasses the redirect to sslsplit.

Because NAT PREROUTING only sees the first packet, a RETURN on the
ClientHello bypasses the entire connection — the redirect never fires.

This module provides:
  - DB-backed matching helpers (should_bypass_sni / should_bypass_ip)
    used for reference and by any future in-process interceptor
  - iptables synchronization (sync_iptables / iptables_status)
    which materializes the enabled SNI rules as RETURN rules placed
    above the REDIRECT rule

The synchronization is called:
  - periodically by ssl_inspect/engine.py (running as root, started by
    the supervisor) so the firewall stays in sync with the DB
  - optionally by the web UI on rule change (only effective if the
    web server happens to run as root, which it does under main.py)

Neither the SNI matching helpers nor the iptables helpers are used by
sslsplit directly. sslsplit always terminates; the firewall decides
which connections reach it.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import subprocess
import threading
import time
from pathlib import Path

from sqlalchemy import select

from logging_config import get_logger
from storage.db import get_session
from storage.models import SslBypassRule

logger = get_logger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
CONF_DIR = _REPO_ROOT / "ssl_inspect" / "conf"

_REFRESH_INTERVAL = 30.0
_lock = threading.Lock()
_rules: list[dict] = []
_last_refresh: float = 0.0


# ---------------------------------------------------------------------------
# DB-backed rules
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# iptables integration
# ---------------------------------------------------------------------------

# iptables --string shows up in the -S output as:
#   -m string --string "example.com" --algo bm
_STRING_RE = re.compile(r'--string\s+"([^"]+)"')


def _sni_needles() -> list[str]:
    """
    Return the SNI patterns that should be present in iptables.

    Wildcards are stripped because -m string matches byte sequences, not
    glob patterns: '*.example.com' is expressed in iptables as the byte
    sequence 'example.com', which appears inside the ClientHello.
    """
    refresh()
    needles: list[str] = []
    with _lock:
        for rule in _rules:
            if rule["match_type"] != "sni":
                continue
            pattern = (rule["pattern"] or "").strip().lower()
            if not pattern:
                continue
            # '*.example.com' → 'example.com'; 'example.com' → 'example.com'
            pattern = pattern.lstrip("*.")
            if pattern:
                needles.append(pattern)
    return sorted(set(needles))


def _iptables(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["iptables", "--wait", *args],
        check=check,
        text=True,
        capture_output=True,
    )


def _installed_needles() -> set[str]:
    """
    Enumerate the SNI bypass rules currently present in the NAT PREROUTING
    chain. Called without root this returns an empty set (the iptables
    command fails and we fail closed).
    """
    result = subprocess.run(
        ["iptables", "--wait", "-t", "nat", "-S", "PREROUTING"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return set()

    needles: set[str] = set()
    for line in result.stdout.splitlines():
        if "-j RETURN" not in line:
            continue
        m = _STRING_RE.search(line)
        if m:
            needles.add(m.group(1))
    return needles


def _iptables_add(needle: str) -> None:
    """
    Insert a RETURN rule for the SNI byte sequence at the top of the
    PREROUTING chain. Using -I PREROUTING 1 ensures the bypass rule is
    evaluated before the redirect, regardless of what else is in the
    chain (firewalld, Docker, VPN clients, etc.).
    """
    _iptables(
        "-t", "nat", "-I", "PREROUTING", "1",
        "-p", "tcp", "--dport", "443",
        "-m", "string", "--string", needle, "--algo", "bm",
        "-j", "RETURN",
    )


def _iptables_delete(needle: str) -> None:
    _iptables(
        "-t", "nat", "-D", "PREROUTING",
        "-p", "tcp", "--dport", "443",
        "-m", "string", "--string", needle, "--algo", "bm",
        "-j", "RETURN",
        check=False,
    )


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows — the interceptor is Linux-only, so this should not happen
        return False


_sync_lock = threading.Lock()


def sync_iptables() -> dict:
    """
    Reconcile the iptables SNI-bypass rules with the current database
    state. Adds rules that are wanted but missing, removes rules that
    are present but no longer wanted.

    Returns a summary dict:
        {"root": bool, "added": int, "removed": int, "unchanged": int}

    Safe to call repeatedly. When not running as root, returns
    {"root": False, ...} without touching iptables.

    A module-level lock serializes concurrent callers (the web UI trigger
    and the interceptor's periodic loop). Without it, two callers could
    both observe a needle as missing and both insert a RETURN rule,
    leaving a permanent duplicate in the chain that the reconciliation
    logic cannot detect because _installed_needles collapses duplicates
    into a set.
    """
    if not _is_root():
        logger.debug("sync_iptables: not running as root; skipping")
        return {"root": False, "added": 0, "removed": 0, "unchanged": 0}

    with _sync_lock:
        wanted = set(_sni_needles())
        installed = _installed_needles()

        added = 0
        removed = 0

        for needle in sorted(wanted - installed):
            try:
                _iptables_add(needle)
                added += 1
            except subprocess.CalledProcessError as exc:
                logger.error(
                    "iptables add failed for %r: %s", needle,
                    (exc.stderr or "").strip(),
                )

        for needle in sorted(installed - wanted):
            try:
                _iptables_delete(needle)
                removed += 1
            except subprocess.CalledProcessError as exc:
                logger.error(
                    "iptables delete failed for %r: %s", needle,
                    (exc.stderr or "").strip(),
                )

        unchanged = len(wanted & installed)

        if added or removed:
            logger.info(
                "iptables bypass sync: added=%d removed=%d unchanged=%d",
                added, removed, unchanged,
            )

        return {"root": True, "added": added, "removed": removed, "unchanged": unchanged}


def iptables_status() -> dict:
    """
    Read-only snapshot for the web UI.

    Returns:
        {
          "root": bool,             # whether the caller is root
          "want": [str, ...],       # SNI needles the DB wants installed
          "have": [str, ...],       # SNI needles actually in iptables
          "missing": [str, ...],    # want - have
          "stale": [str, ...],      # have - want
        }
    """
    want = set(_sni_needles())

    if not _is_root():
        return {
            "root": False,
            "want": sorted(want),
            "have": [],
            "missing": sorted(want),
            "stale": [],
        }

    have = _installed_needles()
    return {
        "root": True,
        "want": sorted(want),
        "have": sorted(have),
        "missing": sorted(want - have),
        "stale": sorted(have - want),
    }