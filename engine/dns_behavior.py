import math
import os
import threading
import time
from collections import defaultdict, deque


_DNS_SHARDS = max(16, int(os.getenv("IDS_DNS_SHARDS", "64") or "64"))
_DNS_EVICT_AT = 10_000

_dns_locks = [threading.Lock() for _ in range(_DNS_SHARDS)]
_dns_activity = [defaultdict(lambda: deque(maxlen=2000)) for _ in range(_DNS_SHARDS)]


def _dns_shard_index(src_ip: str) -> int:
    return hash(src_ip) % _DNS_SHARDS

# Heuristic thresholds (tunable, thesis-friendly)
DNS_WINDOW_SECONDS = 60
DNS_LONG_QNAME = 60
DNS_ENTROPY_SUSPICIOUS = 3.8
DNS_UNIQUE_QNAMES_SUSPICIOUS = 40
DNS_TXT_RATE_SUSPICIOUS = 15
DNS_NXDOMAIN_RATE_SUSPICIOUS = 25  # if you later feed rcode from Zeek DNS


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


_TWO_LEVEL_SUFFIXES = {
    "co.uk", "ac.uk", "gov.uk", "org.uk",
    "co.jp", "ne.jp", "or.jp",
    "com.au", "net.au", "org.au",
    "com.br", "com.cn", "com.tr",
    # extend as needed
}

def _base_domain(qname: str) -> str:
    q = (qname or "").strip(".").lower()
    parts = [p for p in q.split(".") if p]
    if len(parts) <= 2:
        return q
    last_two = ".".join(parts[-2:])
    if last_two in _TWO_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def detect_dns(src_ip: str, dns_event: dict | None) -> list[str]:
    """
    Returns a list of DNS-related behavior reasons (may be empty).
    dns_event: {"qname": str, "qtype": str|int, "qdcount": int, ...}
    """
    if not src_ip or not dns_event:
        return []

    qname = (dns_event.get("qname") or "").strip()
    qtype = str(dns_event.get("qtype") or "").upper()

    if not qname:
        return []

    shard = _dns_shard_index(src_ip)
    lock = _dns_locks[shard]
    table = _dns_activity[shard]

    # Everything that mutates the shard table, appends to the deque, trims
    # the window, or reads the deque happens inside the lock. The heuristic
    # pass runs on an explicit snapshot (list(activity)) taken while the
    # lock is held, so the counts are computed against a stable view even
    # if another thread appends to the same src_ip a moment later.
    with lock:
        now = time.time()

        activity = table.get(src_ip)
        if activity is None:
            activity = deque(maxlen=2000)
            table[src_ip] = activity
            if len(table) > _DNS_EVICT_AT:
                cutoff = now - DNS_WINDOW_SECONDS
                stale = [
                    ip for ip, dq in table.items()
                    if not dq or dq[-1]["time"] < cutoff
                ]
                for ip in stale:
                    table.pop(ip, None)

        activity.append({
            "time": now,
            "qname": qname,
            "qtype": qtype,
            "base": _base_domain(qname),
            "len": len(qname),
            "entropy": shannon_entropy(qname.replace(".", "")),
        })

        # Drop old events — inside the lock so the trim can't race against
        # another thread's append on the same deque.
        cutoff = now - DNS_WINDOW_SECONDS
        while activity and activity[0]["time"] < cutoff:
            activity.popleft()

        # Snapshot for the heuristic pass. Cheap for typical window sizes
        # (a few dozen to a few hundred entries), and lets us release the
        # lock before doing the O(N) work below.
        snapshot = list(activity)

    reasons: list[str] = []

    if not snapshot:
        return reasons

    # Single-event heuristics
    last = snapshot[-1]
    if last["len"] >= DNS_LONG_QNAME:
        reasons.append("dns_long_qname")
    if last["entropy"] >= DNS_ENTROPY_SUSPICIOUS:
        reasons.append("dns_high_entropy_qname")
    # A single TXT query is normal (SPF, DKIM, various CDN health checks).
    # Only mark it when it's part of a burst or combined with high entropy.
    if qtype == "TXT" and (
        last["entropy"] >= DNS_ENTROPY_SUSPICIOUS
        or last["len"] >= DNS_LONG_QNAME
    ):
        reasons.append("dns_txt_query")

    # Window heuristics — all on the snapshot, not on the live deque.
    unique_qnames = len({e["qname"] for e in snapshot})
    if unique_qnames >= DNS_UNIQUE_QNAMES_SUSPICIOUS:
        reasons.append("dns_many_unique_queries")

    txt_count = sum(1 for e in snapshot if e["qtype"] == "TXT")
    if txt_count >= DNS_TXT_RATE_SUSPICIOUS:
        reasons.append("dns_txt_burst")

    # Subdomain churn to one base domain (common in tunneling)
    by_base = defaultdict(set)
    for e in snapshot:
        by_base[e["base"]].add(e["qname"])
    if by_base:
        worst_base, worst_count = max(
            ((b, len(s)) for b, s in by_base.items()), key=lambda x: x[1]
        )
        if worst_count >= 25 and worst_base:
            reasons.append("dns_subdomain_churn")

    # Escalation marker (useful for correlation)
    if ("dns_high_entropy_qname" in reasons and "dns_many_unique_queries" in reasons) or (
        "dns_subdomain_churn" in reasons and "dns_long_qname" in reasons
    ):
        reasons.append("dns_tunnel_suspected")

    return reasons

