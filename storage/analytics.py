"""
Threat pattern aggregation and analytics queries.

Reads suspicious/dangerous rows from packet_logs, buckets them into
hourly/daily/weekly/monthly rows in threat_patterns, and provides
read-only query functions for the analytics dashboard.

Aggregation is idempotent: each run DELETEs the bucket range it's about
to write, then INSERTs fresh rows. Running twice produces the same result.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import delete, distinct, func, select

from logging_config import get_logger
from storage.db import get_session
from storage.models import PacketLog, ThreatPattern

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Bucket boundaries
# ---------------------------------------------------------------------------

def _bucket_hourly(ts: float) -> float:
    return float(int(ts // 3600) * 3600)


def _bucket_daily(ts: float) -> float:
    return float(int(ts // 86400) * 86400)


def _bucket_weekly(ts: float) -> float:
    # Monday-anchored weeks. Unix epoch (1970-01-01) was a Thursday, so
    # shift by 4 days to align bucket edges to Monday 00:00 UTC.
    return float(int((ts + 4 * 86400) // (7 * 86400)) * (7 * 86400) - 4 * 86400)


def _bucket_monthly(ts: float) -> float:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    return float(dt.timestamp())


_BUCKET_FN = {
    "hourly": _bucket_hourly,
    "daily": _bucket_daily,
    "weekly": _bucket_weekly,
    "monthly": _bucket_monthly,
}

# How far back each bucket type is recomputed on every run. Overlapping
# windows ensure late-arriving rows (which can happen because the log
# writer batches asynchronously) are counted exactly once.
_LOOKBACK = {
    "hourly": 3 * 24 * 3600,        # 3 days
    "daily": 14 * 24 * 3600,        # 2 weeks
    "weekly": 12 * 7 * 24 * 3600,   # 12 weeks
    "monthly": 365 * 24 * 3600,     # 1 year
}

# Retention: drop rows older than this. The analytics page only queries
# the last 90 days, so keeping older rows is wasted space.
_RETENTION = {
    "hourly": 14 * 24 * 3600,       # 2 weeks of hourly is plenty
    "daily": 180 * 24 * 3600,       # 6 months
    "weekly": 3 * 365 * 24 * 3600,  # 3 years
    "monthly": 10 * 365 * 24 * 3600,
}


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract_host(url: str | None, http_json: str | None) -> str | None:
    """Prefer the explicit HTTP Host header; fall back to urlparse(url)."""
    if http_json:
        try:
            http = json.loads(http_json)
            if isinstance(http, dict):
                host = http.get("host")
                if host:
                    return str(host).split(":")[0].lower()[:255]
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass
    if not url:
        return None
    try:
        raw = url if "://" in url else f"http://{url}"
        host = urlparse(raw).hostname
        return host.lower()[:255] if host else None
    except Exception:
        return None


def _extract_category(reasons_json: str | None) -> str | None:
    """
    Pick a single "primary" threat category from the reasons list.
    Preference order: payload_* / http_* > reputation_* > ml_attack /
    anomaly > first reason. Keeps the category column low-cardinality so
    the top-threats query returns meaningful groups.
    """
    if not reasons_json:
        return None
    try:
        reasons = json.loads(reasons_json)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(reasons, list) or not reasons:
        return None

    # Reputation verdicts of "safe" are positive signals, not threats.
    # If they reached this list alongside attack signals, they arrived via
    # the TI enrichment step that tags every lookup — they must not be
    # reported as the event's "top threat category".
    _POSITIVE_REPUTATION = {
        "reputation_ip_safe",
        "reputation_url_safe",
        "reputation_ip_unknown",
        "reputation_url_unknown",
    }

    ranked = []
    for r in reasons:
        if not isinstance(r, str):
            continue
        if r in _POSITIVE_REPUTATION:
            continue
        if r.startswith(("http_", "payload_")):
            ranked.append((0, r))
        elif r in ("ml_attack", "anomaly", "strong_anomaly_detected",
                   "high_rf_attack_probability", "combined_ml_signals"):
            ranked.append((1, r))
        elif r.startswith("reputation_"):
            # Suspicious / malicious reputation reasons are meaningful,
            # but they should rank below concrete content matches and
            # concrete ML attack signals.
            ranked.append((2, r))
        else:
            ranked.append((3, r))
    if not ranked:
        return None
    ranked.sort(key=lambda x: x[0])
    return ranked[0][1][:64]


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _aggregate_bucket_type(bucket_type: str, lookback_sec: float) -> int:
    """Recompute one bucket type for the last `lookback_sec` seconds."""
    now = time.time()
    since_ts = now - lookback_sec
    bucket_fn = _BUCKET_FN[bucket_type]

    session = get_session()
    try:
        # Delete rows in the range we're about to rewrite. Idempotency hinges
        # on this — an incremental upsert would double-count on retries.
        deleted = session.execute(
            delete(ThreatPattern)
            .where(ThreatPattern.bucket_type == bucket_type)
            .where(ThreatPattern.bucket_start >= since_ts)
        ).rowcount or 0

        # Pull every suspicious/dangerous event in the range. Bounded by the
        # lookback window, so at most a few days of data per run.
        rows = session.execute(
            select(
                PacketLog.timestamp,
                PacketLog.src_ip,
                PacketLog.url,
                PacketLog.http_json,
                PacketLog.classification,
                PacketLog.risk_score,
                PacketLog.reasons_json,
            )
            .where(PacketLog.timestamp >= since_ts)
            .where(PacketLog.classification.in_(("suspicious", "dangerous")))
        ).all()

        # Group in Python. The tuples are low-cardinality per bucket
        # (src_ip × host × category), so this stays small.
        agg: dict[tuple, dict] = {}
        for ts, src_ip, url, http_json, cls, risk, reasons_json in rows:
            bucket_start = bucket_fn(float(ts))
            host = _extract_host(url, http_json)
            category = _extract_category(reasons_json)

            key = (bucket_start, src_ip, host, category)
            entry = agg.get(key)
            if entry is None:
                entry = {
                    "event_count": 0,
                    "dangerous_count": 0,
                    "suspicious_count": 0,
                    "max_risk_score": 0.0,
                }
                agg[key] = entry
            entry["event_count"] += 1
            if cls == "dangerous":
                entry["dangerous_count"] += 1
            else:
                entry["suspicious_count"] += 1
            try:
                r = float(risk or 0.0)
            except (TypeError, ValueError):
                r = 0.0
            if r > entry["max_risk_score"]:
                entry["max_risk_score"] = r

        if not agg:
            session.commit()
            return 0

        session.add_all([
            ThreatPattern(
                bucket_type=bucket_type,
                bucket_start=bs,
                src_ip=src_ip,
                host=host,
                threat_category=category,
                event_count=entry["event_count"],
                dangerous_count=entry["dangerous_count"],
                suspicious_count=entry["suspicious_count"],
                max_risk_score=entry["max_risk_score"] or None,
            )
            for (bs, src_ip, host, category), entry in agg.items()
        ])
        session.commit()
        logger.info(
            "Analytics: bucket=%s rewrote %d rows (deleted %d, aggregated %d events)",
            bucket_type, len(agg), deleted, len(rows),
        )
        return len(agg)
    except Exception:
        session.rollback()
        logger.error("Analytics aggregation failed (bucket=%s)", bucket_type, exc_info=True)
        return 0
    finally:
        session.close()


def run_analytics_aggregation() -> dict[str, int]:
    """Aggregate all four bucket types. Called hourly by the worker."""
    result = {}
    for bucket_type, lookback in _LOOKBACK.items():
        result[bucket_type] = _aggregate_bucket_type(bucket_type, lookback)
    _cleanup_retention()
    return result


def _cleanup_retention() -> None:
    """Drop analytics rows that have aged out of every query's window."""
    now = time.time()
    session = get_session()
    try:
        for bucket_type, keep_sec in _RETENTION.items():
            cutoff = now - keep_sec
            session.execute(
                delete(ThreatPattern)
                .where(ThreatPattern.bucket_type == bucket_type)
                .where(ThreatPattern.bucket_start < cutoff)
            )
        session.commit()
    except Exception:
        session.rollback()
        logger.error("Analytics retention cleanup failed", exc_info=True)
    finally:
        session.close()


def start_analytics_worker(interval_sec: int = 3600) -> None:
    """Background loop. Same pattern as start_retention_worker."""
    # Small initial delay so the first run happens after startup settles.
    time.sleep(30)
    while True:
        try:
            run_analytics_aggregation()
        except Exception:
            logger.error("Analytics worker iteration failed", exc_info=True)
        time.sleep(interval_sec)


# ---------------------------------------------------------------------------
# Query functions for the API
# ---------------------------------------------------------------------------

def get_heatmap(weeks: int = 4) -> dict:
    """
    Day-of-week × hour-of-day grid of dangerous event counts.
    Returns {'labels': [...24 hours...], 'rows': [{'day': 'Mon', 'cells': [...]}, ...]}
    """
    weeks = max(1, min(int(weeks), 26))
    since = time.time() - weeks * 7 * 86400

    session = get_session()
    try:
        rows = session.execute(
            select(ThreatPattern.bucket_start, ThreatPattern.dangerous_count)
            .where(ThreatPattern.bucket_type == "hourly")
            .where(ThreatPattern.bucket_start >= since)
        ).all()
    finally:
        session.close()

    # 7 days × 24 hours accumulator
    grid = [[0] * 24 for _ in range(7)]
    for bucket_start, dangerous_count in rows:
        dt = datetime.fromtimestamp(float(bucket_start), tz=timezone.utc)
        # Python weekday(): Monday=0 ... Sunday=6. Same convention for the grid.
        grid[dt.weekday()][dt.hour] += int(dangerous_count or 0)

    max_val = max((max(r) for r in grid), default=0)
    day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    return {
        "hours": [f"{h:02d}" for h in range(24)],
        "rows": [
            {"day": day_names[i], "cells": grid[i]}
            for i in range(7)
        ],
        "max": max_val,
        "weeks": weeks,
    }


def get_recurring_actors(
    *,
    field: str = "src_ip",
    min_days: int = 3,
    lookback_days: int = 30,
    limit: int = 50,
) -> list[dict]:
    """
    IPs (or hosts) that appear on >= min_days distinct days.
    Uses daily buckets so "distinct day" is unambiguous.
    """
    if field not in ("src_ip", "host"):
        raise ValueError("field must be 'src_ip' or 'host'")

    since = time.time() - lookback_days * 86400
    col = ThreatPattern.src_ip if field == "src_ip" else ThreatPattern.host

    session = get_session()
    try:
        stmt = (
            select(
                col.label("actor"),
                func.count(distinct(ThreatPattern.bucket_start)).label("days_active"),
                func.sum(ThreatPattern.event_count).label("total_events"),
                func.sum(ThreatPattern.dangerous_count).label("total_dangerous"),
                func.max(ThreatPattern.max_risk_score).label("worst_risk"),
                func.min(ThreatPattern.bucket_start).label("first_seen"),
                func.max(ThreatPattern.bucket_start).label("last_seen"),
            )
            .where(ThreatPattern.bucket_type == "daily")
            .where(ThreatPattern.bucket_start >= since)
            .where(col.isnot(None))
            .group_by(col)
            .having(func.count(distinct(ThreatPattern.bucket_start)) >= int(min_days))
            .order_by(func.count(distinct(ThreatPattern.bucket_start)).desc())
            .limit(int(limit))
        )
        rows = session.execute(stmt).all()
    finally:
        session.close()

    out = []
    for actor, days, total, dangerous, worst, first_ts, last_ts in rows:
        if not actor:
            continue
        out.append({
            "actor": actor,
            "days_active": int(days or 0),
            "total_events": int(total or 0),
            "total_dangerous": int(dangerous or 0),
            "worst_risk": round(float(worst or 0), 3),
            "first_seen": float(first_ts or 0),
            "last_seen": float(last_ts or 0),
        })
    return out


def get_top_threats(
    *,
    lookback_days: int = 30,
    limit: int = 15,
) -> list[dict]:
    """Threat categories ranked by event count over the lookback window."""
    since = time.time() - lookback_days * 86400

    session = get_session()
    try:
        rows = session.execute(
            select(
                ThreatPattern.threat_category,
                func.sum(ThreatPattern.event_count).label("total"),
                func.sum(ThreatPattern.dangerous_count).label("dangerous"),
            )
            .where(ThreatPattern.bucket_type == "daily")
            .where(ThreatPattern.bucket_start >= since)
            .where(ThreatPattern.threat_category.isnot(None))
            .group_by(ThreatPattern.threat_category)
            .order_by(func.sum(ThreatPattern.event_count).desc())
            .limit(int(limit))
        ).all()
    finally:
        session.close()

    return [
        {
            "category": str(cat),
            "total_events": int(total or 0),
            "dangerous_events": int(dangerous or 0),
        }
        for cat, total, dangerous in rows
    ]


def get_periodic_patterns(
    *,
    field: str = "src_ip",
    lookback_days: int = 60,
    min_weeks: int = 3,
    min_share: float = 0.55,
    limit: int = 20,
) -> list[dict]:
    """
    Find (actor, day_of_week) pairs where the actor's events cluster on a
    single weekday. This is what drives the "every Friday, IP X attacks" cards.

    Approach:
      1. For each actor, load all daily buckets in the window.
      2. Sum events per weekday.
      3. If one weekday has >= min_share of total events AND the actor
         appears in >= min_weeks distinct weeks, flag it.
    """
    if field not in ("src_ip", "host"):
        raise ValueError("field must be 'src_ip' or 'host'")

    since = time.time() - lookback_days * 86400
    col = ThreatPattern.src_ip if field == "src_ip" else ThreatPattern.host

    session = get_session()
    try:
        rows = session.execute(
            select(
                col.label("actor"),
                ThreatPattern.bucket_start,
                ThreatPattern.event_count,
                ThreatPattern.threat_category,
            )
            .where(ThreatPattern.bucket_type == "daily")
            .where(ThreatPattern.bucket_start >= since)
            .where(col.isnot(None))
        ).all()
    finally:
        session.close()

    # Group by actor
    by_actor: dict[str, list[tuple[float, int, str | None]]] = {}
    for actor, bucket_start, event_count, category in rows:
        if not actor:
            continue
        by_actor.setdefault(str(actor), []).append(
            (float(bucket_start), int(event_count or 0), category)
        )

    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    found: list[dict] = []

    for actor, entries in by_actor.items():
        if not entries:
            continue

        per_dow = [0] * 7
        per_dow_weeks: list[set[int]] = [set() for _ in range(7)]
        per_dow_categories: list[dict[str, int]] = [{} for _ in range(7)]
        total = 0

        for bucket_start, count, category in entries:
            dt = datetime.fromtimestamp(bucket_start, tz=timezone.utc)
            dow = dt.weekday()
            per_dow[dow] += count
            total += count
            # ISO week number + year uniquely identifies a week
            per_dow_weeks[dow].add(dt.isocalendar()[1] + dt.year * 100)
            if category:
                per_dow_categories[dow][category] = per_dow_categories[dow].get(category, 0) + count

        if total == 0:
            continue

        best_dow = max(range(7), key=lambda i: per_dow[i])
        share = per_dow[best_dow] / total
        weeks_observed = len(per_dow_weeks[best_dow])

        if share >= min_share and weeks_observed >= min_weeks:
            top_category = None
            if per_dow_categories[best_dow]:
                top_category = max(
                    per_dow_categories[best_dow].items(), key=lambda kv: kv[1]
                )[0]
            found.append({
                "actor": actor,
                "field": field,
                "day_of_week": best_dow,
                "day_name": day_names[best_dow],
                "share": round(share, 3),
                "weeks_observed": weeks_observed,
                "avg_events_per_week": round(per_dow[best_dow] / max(1, weeks_observed), 1),
                "total_events": total,
                "top_category": top_category,
            })

    # Highest-signal patterns first: confidence × volume
    found.sort(key=lambda x: (x["share"] * x["weeks_observed"], x["total_events"]), reverse=True)
    return found[:limit]


def get_weekly_summary(weeks: int = 12) -> dict:
    """
    Weekly totals for the top-of-page summary cards.
    Returns {'labels': ['Wk 12', ...], 'dangerous': [...], 'suspicious': [...]}
    """
    weeks = max(1, min(int(weeks), 52))
    since = time.time() - weeks * 7 * 86400

    session = get_session()
    try:
        rows = session.execute(
            select(
                ThreatPattern.bucket_start,
                func.sum(ThreatPattern.dangerous_count).label("d"),
                func.sum(ThreatPattern.suspicious_count).label("s"),
            )
            .where(ThreatPattern.bucket_type == "weekly")
            .where(ThreatPattern.bucket_start >= since)
            .group_by(ThreatPattern.bucket_start)
            .order_by(ThreatPattern.bucket_start)
        ).all()
    finally:
        session.close()

    labels, dangerous, suspicious = [], [], []
    for bucket_start, d, s in rows:
        dt = datetime.fromtimestamp(float(bucket_start), tz=timezone.utc)
        labels.append(dt.strftime("%Y-%m-%d"))
        dangerous.append(int(d or 0))
        suspicious.append(int(s or 0))

    return {
        "labels": labels,
        "dangerous": dangerous,
        "suspicious": suspicious,
        "totals": {
            "dangerous": sum(dangerous),
            "suspicious": sum(suspicious),
            "weeks": len(labels),
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main() -> int:
    import dotenv
    dotenv.load_dotenv()

    parser = argparse.ArgumentParser(description="Analytics aggregation CLI")
    parser.add_argument("--backfill", action="store_true",
                        help="Recompute all buckets over a longer window")
    parser.add_argument("--days", type=int, default=30,
                        help="Backfill window in days (default 30)")
    args = parser.parse_args()

    if args.backfill:
        # Temporarily widen lookback for each bucket type so old packets
        # are covered.
        from storage.analytics import _LOOKBACK as LB
        original = dict(LB)
        try:
            for k in LB:
                LB[k] = max(LB[k], args.days * 86400)
            result = run_analytics_aggregation()
            print(json.dumps({"backfilled": result, "days": args.days}, indent=2))
        finally:
            LB.clear()
            LB.update(original)
        return 0

    result = run_analytics_aggregation()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())