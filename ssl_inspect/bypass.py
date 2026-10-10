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
  - periodically by ssl_inspect/engine.py so the firewall stays in sync
    with the DB
  - optionally by the web UI on rule change

Privileges: this module works in three modes.

  1. Running as root — iptables is invoked directly.
  2. Running as an unprivileged user with a passwordless sudoers rule
     for the exact iptables invocations listed below. See the README
     section "Running as a non-root user", Option B.
  3. Running as an unprivileged user with neither — sync_iptables()
     and iptables_status() return {"root": False, ...} without
     touching the firewall, and the interceptor logs the condition.

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
# Privilege helpers
# ---------------------------------------------------------------------------

def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _iptables_cmd(*args: str) -> list[str]:
    """
    Build the iptables argv, prefixing with `sudo -n` when not root.

    `-n` is critical: it tells sudo to fail immediately if a password
    would be required, rather than hanging on a prompt. In a background
    thread (the interceptor's sync loop) a hanging prompt would deadlock
    the whole worker.

    The sudoers rule in the README grants passwordless access to the
    exact invocations this module makes, so `sudo -n` succeeds on any
    host that has been set up per Option B.
    """
    base = ["iptables", "--wait", *args]
    if _is_root():
        return base
    return ["sudo", "-n", *base]


# Cache the probe so the sync loop doesn't fork a `sudo` process every
# 30 seconds just to check whether we can run iptables.
_can_run_cache: bool | None = None


def _can_run_iptables() -> bool:
    """
    Return True if this process can execute iptables commands — either
    because it is root, or because passwordless sudo is configured for
    the specific invocations this module makes.

    Probed once per process. The probe is a harmless read
    (`iptables -t nat -L PREROUTING -n`) that requires no state change.
    """
    global _can_run_cache
    if _can_run_cache is not None:
        return _can_run_cache

    if _is_root():
        _can_run_cache = True
        return True

    try:
        probe = subprocess.run(
            ["sudo", "-n", "iptables", "--wait", "-t", "nat", "-L", "PREROUTING", "-n"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        _can_run_cache = probe.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        _can_run_cache = False

    return _can_run_cache


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
            pattern = pattern.lstrip("*.")
            if pattern:
                needles.append(pattern)
    return sorted(set(needles))


def _iptables(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        _iptables_cmd(*args),
        check=check,
        text=True,
        capture_output=True,
    )


def _installed_needles() -> set[str]:
    """
    Enumerate the SNI bypass rules currently present in the NAT PREROUTING
    chain. Returns an empty set if iptables cannot be queried (no root,
    no sudoers) — the caller reconciles against an empty set, which
    means "add everything the DB wants", and the add attempts fail
    gracefully if we also can't write.
    """
    result = subprocess.run(
        _iptables_cmd("-t", "nat", "-S", "PREROUTING"),
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


_sync_lock = threading.Lock()


def sync_iptables() -> dict:
    """
    Reconcile the iptables SNI-bypass rules with the current database
    state. Adds rules that are wanted but missing, removes rules that
    are present but no longer wanted.

    Returns a summary dict:
        {"root": bool, "added": int, "removed": int, "unchanged": int}

    `root` here means "we were able to run iptables" — either because
    the process is root or because passwordless sudo is configured.
    When neither is true, returns {"root": False, ...} without
    touching iptables.

    A module-level lock serializes concurrent callers (the web UI trigger
    and the interceptor's periodic loop). Without it, two callers could
    both observe a needle as missing and both insert a RETURN rule,
    leaving a permanent duplicate in the chain that the reconciliation
    logic cannot detect because _installed_needles collapses duplicates
    into a set.
    """
    if not _can_run_iptables():
        logger.debug(
            "sync_iptables: iptables not available (not root, no sudoers "
            "rule). See README §Running as a non-root user, Option B."
        )
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
            except (subprocess.CalledProcessError, FileNotFoundError) as exc:
                stderr = getattr(exc, "stderr", "") or ""
                logger.error("iptables add failed for %r: %s", needle, stderr.strip())

        for needle in sorted(installed - wanted):
            try:
                _iptables_delete(needle)
                removed += 1
            except (subprocess.CalledProcessError, FileNotFoundError) as exc:
                stderr = getattr(exc, "stderr", "") or ""
                logger.error("iptables delete failed for %r: %s", needle, stderr.strip())

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
          "root": bool,             # whether iptables is usable
          "want": [str, ...],       # SNI needles the DB wants installed
          "have": [str, ...],       # SNI needles actually in iptables
          "missing": [str, ...],    # want - have
          "stale": [str, ...],      # have - want
        }
    """
    want = set(_sni_needles())

    if not _can_run_iptables():
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