import math
import time
from collections import defaultdict, deque


dns_activity = defaultdict(lambda: deque(maxlen=2000))

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


def _base_domain(qname: str) -> str:
    q = (qname or "").strip(".").lower()
    parts = [p for p in q.split(".") if p]
    if len(parts) <= 2:
        return q
    return ".".join(parts[-2:])


def detect_dns(src_ip: str, dns_event: dict | None) -> list[str]:
    """
    Returns a list of DNS-related behavior reasons (may be empty).
    dns_event: {"qname": str, "qtype": str|int, "qdcount": int, ...}
    """
    if not src_ip or not dns_event:
        return []

    now = time.time()
    qname = (dns_event.get("qname") or "").strip()
    qtype = str(dns_event.get("qtype") or "").upper()

    if not qname:
        return []

    activity = dns_activity[src_ip]
    activity.append(
        {
            "time": now,
            "qname": qname,
            "qtype": qtype,
            "base": _base_domain(qname),
            "len": len(qname),
            "entropy": shannon_entropy(qname.replace(".", "")),
        }
    )

    # Drop old events
    cutoff = now - DNS_WINDOW_SECONDS
    while activity and activity[0]["time"] < cutoff:
        activity.popleft()

    reasons: list[str] = []

    # Single-event heuristics
    last = activity[-1]
    if last["len"] >= DNS_LONG_QNAME:
        reasons.append("dns_long_qname")
    if last["entropy"] >= DNS_ENTROPY_SUSPICIOUS:
        reasons.append("dns_high_entropy_qname")
    if qtype == "TXT":
        reasons.append("dns_txt_query")

    # Window heuristics
    unique_qnames = len({e["qname"] for e in activity})
    if unique_qnames >= DNS_UNIQUE_QNAMES_SUSPICIOUS:
        reasons.append("dns_many_unique_queries")

    txt_count = sum(1 for e in activity if e["qtype"] == "TXT")
    if txt_count >= DNS_TXT_RATE_SUSPICIOUS:
        reasons.append("dns_txt_burst")

    # Subdomain churn to one base domain (common in tunneling)
    by_base = defaultdict(set)
    for e in activity:
        by_base[e["base"]].add(e["qname"])
    if by_base:
        worst_base, worst_count = max(((b, len(s)) for b, s in by_base.items()), key=lambda x: x[1])
        if worst_count >= 25 and worst_base:
            reasons.append("dns_subdomain_churn")

    # Escalation marker (useful for correlation)
    if ("dns_high_entropy_qname" in reasons and "dns_many_unique_queries" in reasons) or (
        "dns_subdomain_churn" in reasons and "dns_long_qname" in reasons
    ):
        reasons.append("dns_tunnel_suspected")

    return reasons

