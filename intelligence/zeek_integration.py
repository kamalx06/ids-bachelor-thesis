from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from pathlib import Path

import dotenv

from logging_config import get_logger

dotenv.load_dotenv()

logger = get_logger(__name__)

ZEEK_LOG = os.environ.get("ZEEK_LOG")
ZEEK_LOG_DIR = os.environ.get("ZEEK_LOG_DIR")
ZEEK_NOTICE_LOG = os.environ.get("ZEEK_NOTICE_LOG")
ZEEK_WEIRD_LOG = os.environ.get("ZEEK_WEIRD_LOG")

# Per-IP connection cache and incremental read offsets per log file
_ip_conn_cache: dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))
_notice_hits: dict[str, list[dict]] = defaultdict(list)
_weird_hits: dict[str, list[dict]] = defaultdict(list)
_file_positions: dict[str, int] = {}

# Structured lookup cache (short TTL)
_lookup_cache: dict[str, tuple[float, dict]] = {}
_LOOKUP_TTL = int(os.environ.get("ZEEK_CACHE_TTL_SECONDS", "30") or "30")

_HIGH_RISK_NOTES = (
    "scan",
    "brute",
    "attack",
    "exploit",
    "malware",
    "dos",
    "ddos",
    "infection",
    "sql",
    "shell",
)


def zeek_logs_available() -> bool:
    """True only when Zeek log files exist on disk (not merely env vars set)."""
    paths = _resolve_log_paths()
    return any(p is not None and p.is_file() for p in paths.values())


def _resolve_log_paths() -> dict[str, Path | None]:
    """Resolve Zeek log paths from env (file path or directory)."""
    paths: dict[str, Path | None] = {"conn": None, "notice": None, "weird": None}

    if ZEEK_LOG:
        conn = Path(ZEEK_LOG)
        if conn.is_file():
            paths["conn"] = conn
            base_dir = conn.parent
        else:
            base_dir = None
    elif ZEEK_LOG_DIR:
        base_dir = Path(ZEEK_LOG_DIR)
    else:
        base_dir = None

    if base_dir and base_dir.is_dir():
        if paths["conn"] is None:
            candidate = base_dir / "conn.log"
            paths["conn"] = candidate if candidate.is_file() else None
        notice = Path(ZEEK_NOTICE_LOG) if ZEEK_NOTICE_LOG else base_dir / "notice.log"
        weird = Path(ZEEK_WEIRD_LOG) if ZEEK_WEIRD_LOG else base_dir / "weird.log"
        paths["notice"] = notice if notice.is_file() else None
        paths["weird"] = weird if weird.is_file() else None
    else:
        if ZEEK_NOTICE_LOG and Path(ZEEK_NOTICE_LOG).is_file():
            paths["notice"] = Path(ZEEK_NOTICE_LOG)
        if ZEEK_WEIRD_LOG and Path(ZEEK_WEIRD_LOG).is_file():
            paths["weird"] = Path(ZEEK_WEIRD_LOG)

    return paths


def _parse_tsv_line(line: str, headers: list[str]) -> dict | None:
    fields = line.rstrip("\n").split("\t")
    if len(fields) != len(headers):
        return None
    return dict(zip(headers, fields))


def _read_zeek_headers(f) -> list[str] | None:
    """Find #fields line in Zeek log header block."""
    pos = f.tell()
    headers = None
    for line in f:
        if line.startswith("#fields"):
            headers = line.strip().split("\t")[1:]
            break
        if not line.startswith("#"):
            break
    if headers is None:
        f.seek(pos)
    return headers


def _tail_read_log(path: Path, handler) -> None:
    """Incrementally read new TSV rows from a Zeek log."""
    key = str(path.resolve())
    if not path.is_file():
        return

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            pos = _file_positions.get(key, 0)
            if pos == 0:
                headers = _read_zeek_headers(f)
                if not headers:
                    return
                _file_positions[key] = f.tell()
                pos = f.tell()
            else:
                f.seek(0)
                headers = _read_zeek_headers(f)
                if not headers:
                    return
                f.seek(pos)

            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                row = _parse_tsv_line(line, headers)
                if row:
                    handler(row)
            _file_positions[key] = f.tell()
    except Exception:
        logger.error("Zeek log read failed: %s", path, exc_info=True)


def _ingest_conn(row: dict) -> None:
    src = row.get("id.orig_h")
    dst = row.get("id.resp_h")
    if src:
        _ip_conn_cache[src].append(row)
    if dst and dst != src:
        _ip_conn_cache[dst].append(row)


def _ingest_notice(row: dict) -> None:
    note = (row.get("note") or row.get("msg") or "").lower()
    for ip in (row.get("id.orig_h"), row.get("id.resp_h"), row.get("src"), row.get("dst")):
        if not ip:
            continue
        _notice_hits[ip].append({"note": note, "ts": row.get("ts"), "row": row})
        if len(_notice_hits[ip]) > 200:
            _notice_hits[ip] = _notice_hits[ip][-200:]


def _ingest_weird(row: dict) -> None:
    name = (row.get("name") or "").lower()
    for ip in (row.get("id.orig_h"), row.get("id.resp_h"), row.get("src"), row.get("dst")):
        if not ip:
            continue
        _weird_hits[ip].append({"name": name, "ts": row.get("ts")})
        if len(_weird_hits[ip]) > 200:
            _weird_hits[ip] = _weird_hits[ip][-200:]


def update_cache() -> None:
    paths = _resolve_log_paths()
    if paths["conn"]:
        _tail_read_log(paths["conn"], _ingest_conn)
    if paths["notice"]:
        _tail_read_log(paths["notice"], _ingest_notice)
    if paths["weird"]:
        _tail_read_log(paths["weird"], _ingest_weird)


def _analyze_connections(ip: str, connections: deque) -> tuple[float, list[str]]:
    """Return (risk_score 0-1, signal list) from conn.log entries."""
    if not connections:
        return 0.0, []

    rejected = 0
    short_lived = 0
    syn_only = 0
    resp_ports: set[str] = set()
    orig_ports: set[str] = set()
    total = len(connections)

    for conn in connections:
        state = (conn.get("conn_state") or "").upper()
        proto = (conn.get("proto") or "").lower()
        try:
            resp_bytes = int(float(conn.get("resp_bytes") or 0))
        except (TypeError, ValueError):
            resp_bytes = 0
        try:
            duration = float(conn.get("duration") or 0)
        except (TypeError, ValueError):
            duration = 0.0

        if "REJ" in state or resp_bytes == 0:
            rejected += 1
        if duration < 0.5 and proto in ("tcp", "udp"):
            short_lived += 1
        if state in ("S0", "SH") or state.startswith("S0"):
            syn_only += 1

        dp = conn.get("id.resp_p")
        sp = conn.get("id.orig_p")
        if dp:
            resp_ports.add(dp)
        if sp:
            orig_ports.add(sp)

    signals: list[str] = []
    score = 0.0

    rej_ratio = rejected / total
    if rej_ratio > 0.5:
        signals.append("zeek_high_reject_ratio")
        score = max(score, 0.7)
    elif rejected > 5:
        signals.append("zeek_many_rejected_conns")
        score = max(score, 0.55)

    if len(resp_ports) >= 15:
        signals.append("zeek_port_scan")
        score = max(score, 0.75)
    elif len(resp_ports) >= 8:
        signals.append("zeek_many_target_ports")
        score = max(score, 0.5)

    if short_lived > 10:
        signals.append("zeek_short_connections")
        score = max(score, 0.45)

    if syn_only > 8:
        signals.append("zeek_syn_scan_pattern")
        score = max(score, 0.6)

    return min(1.0, score), signals


def _analyze_notices(ip: str) -> tuple[float, list[str]]:
    hits = _notice_hits.get(ip, [])
    if not hits:
        return 0.0, []

    signals: list[str] = []
    score = 0.0
    for hit in hits[-50:]:
        note = hit.get("note") or ""
        if any(token in note for token in _HIGH_RISK_NOTES):
            signals.append(f"zeek_notice_{note[:40]}")
            score = max(score, 0.85)
    if hits and score == 0.0:
        signals.append("zeek_notice_activity")
        score = 0.4
    return score, signals


def _analyze_weird(ip: str) -> tuple[float, list[str]]:
    hits = _weird_hits.get(ip, [])
    if not hits:
        return 0.0, []

    signals = ["zeek_weird_activity"]
    count = len(hits)
    if count > 20:
        return 0.7, signals + ["zeek_heavy_weird"]
    if count > 5:
        return 0.5, signals
    return 0.35, signals


def lookup_ip(ip: str) -> dict:
    """
    Structured Zeek enrichment for an IP.
    """
    cached = _lookup_cache.get(ip)
    if cached and time.time() < cached[0]:
        return cached[1]

    logs_ok = zeek_logs_available()
    neutral = {
        "type": "ip",
        "indicator": ip,
        "provider": "zeek",
        "verdict": "unknown",
        "score": 0.0,
        "signals": [],
        "logs_available": False,
        "reason": None,
    }
    if not logs_ok:
        _lookup_cache[ip] = (time.time() + _LOOKUP_TTL, neutral)
        return neutral

    update_cache()

    result = {
        "type": "ip",
        "indicator": ip,
        "provider": "zeek",
        "verdict": "unknown",
        "score": 0.0,
        "signals": [],
        "logs_available": True,
    }

    connections = _ip_conn_cache.get(ip, deque())
    scores: list[float] = []
    all_signals: list[str] = []

    if connections:
        s, sig = _analyze_connections(ip, connections)
        scores.append(s)
        all_signals.extend(sig)

    s, sig = _analyze_notices(ip)
    if sig:
        scores.append(s)
        all_signals.extend(sig)

    s, sig = _analyze_weird(ip)
    if sig:
        scores.append(s)
        all_signals.extend(sig)

    if scores:
        result["score"] = max(scores)
    result["signals"] = list(dict.fromkeys(all_signals))  # dedupe, preserve order

    if result["score"] >= 0.7:
        result["verdict"] = "malicious"
        result["reason"] = "zeek_flag_dangerous"
    elif result["score"] >= 0.4:
        result["verdict"] = "suspicious"
        result["reason"] = "zeek_flag_suspicious"
    else:
        result["verdict"] = "safe" if connections or _notice_hits.get(ip) else "unknown"
        result["reason"] = None

    _lookup_cache[ip] = (time.time() + _LOOKUP_TTL, result)
    return result


def check_ip(ip: str) -> str | None:
    """Legacy: return a reason token for main.py, or None."""
    data = lookup_ip(ip)
    return data.get("reason")


# Sniffer compatibility alias
check = check_ip
