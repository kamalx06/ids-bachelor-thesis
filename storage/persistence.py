from __future__ import annotations

import json
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert

from logging_config import get_logger
from storage.db import get_session, shutdown_session
from storage.models import (
    AiAnalysisHistory,
    DangerousIp,
    IdsStatistics,
    PacketLog,
    ThreatIntelCache,
)
from ids.event_timestamp import resolve_event_epoch_seconds

logger = get_logger(__name__)

_STATS_LOCK = threading.Lock()
_FLUSH_LOCK = threading.Lock()
_STATS_PERSIST_INTERVAL = float(__import__("os").getenv("IDS_STATS_PERSIST_INTERVAL", "2") or "2")
_last_stats_persist = 0.0
_LOG_BATCH: deque[dict] = deque()
_AI_BATCH: deque[dict] = deque()
_TRAINING_BATCH: deque[dict] = deque()
_BATCH_SIZE = max(1, int(__import__("os").getenv("IDS_DB_BATCH_SIZE", "50") or "50"))
_FLUSH_INTERVAL = float(__import__("os").getenv("IDS_DB_FLUSH_INTERVAL", "0.5") or "0.5")
_TI_TTL_SECONDS = int(__import__("os").getenv("IDS_TI_CACHE_TTL", "3600") or "3600")
_RETENTION_DAYS = int(__import__("os").getenv("IDS_LOG_RETENTION_DAYS", "7") or "7")
_TRAINING_ENABLED = (__import__("os").getenv("IDS_TRAINING_ENABLED", "true") or "true").lower() == "true"
_TRAINING_SAFE_RATE = float(__import__("os").getenv("IDS_TRAINING_SAFE_SAMPLE_RATE", "0.02") or "0.02")

# In-memory mirror for fast telemetry (synced to MySQL)
_live_stats: dict[str, Any] = {
    "total": 0,
    "safe": 0,
    "suspicious": 0,
    "dangerous": 0,
    "unique_attackers": set(),
    "dangerous_ips": set(),
    "dangerous_urls": set(),
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _json_dumps(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return json.dumps(str(value), ensure_ascii=False)


def _to_native(value: Any) -> Any:
    """Convert numpy scalars and other non-JSON types for MySQL drivers."""
    if value is None:
        return None
    if hasattr(value, "item") and callable(value.item):
        try:
            return value.item()
        except Exception:
            pass
    if isinstance(value, float):
        return float(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return int(value)
    return value


def _json_load_set(raw: str | None) -> set[str]:
    if not raw:
        return set()
    try:
        data = json.loads(raw)
        return set(data) if isinstance(data, list) else set()
    except Exception:
        return set()


def init_persistence() -> None:
    from storage.migrations import run_migrations

    run_migrations()
    restore_statistics()
    logger.info("Persistence layer initialized; stats restored from MySQL")


def get_live_stats() -> dict[str, Any]:
    with _STATS_LOCK:
        return {
            "total": _live_stats["total"],
            "safe": _live_stats["safe"],
            "suspicious": _live_stats["suspicious"],
            "dangerous": _live_stats["dangerous"],
            "unique_attackers": set(_live_stats["unique_attackers"]),
            "dangerous_ips": set(_live_stats["dangerous_ips"]),
            "dangerous_urls": set(_live_stats["dangerous_urls"]),
        }


def restore_statistics() -> None:
    """Load persistent counters from ids_statistics singleton."""
    session = get_session()
    try:
        row = session.get(IdsStatistics, 1)
        if row is None:
            row = IdsStatistics(id=1)
            session.add(row)
            session.commit()
            return

        with _STATS_LOCK:
            _live_stats["total"] = int(row.total_events or 0)
            _live_stats["safe"] = int(row.safe_count or 0)
            _live_stats["suspicious"] = int(row.suspicious_count or 0)
            _live_stats["dangerous"] = int(row.dangerous_count or 0)
            _live_stats["unique_attackers"] = _json_load_set(row.unique_attackers_json)
            _live_stats["dangerous_ips"] = _json_load_set(row.dangerous_ips_json)
            _live_stats["dangerous_urls"] = _json_load_set(row.dangerous_urls_json)
            _mirror_stats_to_memory_store_unlocked()

        logger.info(
            "Restored IDS statistics: total=%d safe=%d suspicious=%d dangerous=%d",
            _live_stats["total"],
            _live_stats["safe"],
            _live_stats["suspicious"],
            _live_stats["dangerous"],
        )
    except Exception:
        logger.error("Failed to restore statistics from MySQL", exc_info=True)
        session.rollback()
    finally:
        session.close()


def _persist_statistics_unlocked() -> None:
    session = get_session()
    try:
        attackers = list(_live_stats["unique_attackers"])
        dangerous_ips = list(_live_stats["dangerous_ips"])
        dangerous_urls = list(_live_stats["dangerous_urls"])

        stmt = (
            mysql_insert(IdsStatistics)
            .values(
                id=1,
                total_events=_live_stats["total"],
                safe_count=_live_stats["safe"],
                suspicious_count=_live_stats["suspicious"],
                dangerous_count=_live_stats["dangerous"],
                unique_attackers_count=len(attackers),
                dangerous_ips_count=len(dangerous_ips),
                unique_attackers_json=_json_dumps(attackers),
                dangerous_ips_json=_json_dumps(dangerous_ips),
                dangerous_urls_json=_json_dumps(dangerous_urls),
                updated_at=_utcnow(),
            )
            .on_duplicate_key_update(
                total_events=_live_stats["total"],
                safe_count=_live_stats["safe"],
                suspicious_count=_live_stats["suspicious"],
                dangerous_count=_live_stats["dangerous"],
                unique_attackers_count=len(attackers),
                dangerous_ips_count=len(dangerous_ips),
                unique_attackers_json=_json_dumps(attackers),
                dangerous_ips_json=_json_dumps(dangerous_ips),
                dangerous_urls_json=_json_dumps(dangerous_urls),
                updated_at=_utcnow(),
            )
        )
        session.execute(stmt)
        session.commit()
    except Exception:
        session.rollback()
        logger.error("Failed to persist statistics", exc_info=True)
    finally:
        session.close()


def _maybe_persist_statistics() -> None:
    global _last_stats_persist
    now = time.time()
    if now - _last_stats_persist < _STATS_PERSIST_INTERVAL:
        return
    _last_stats_persist = now
    _persist_statistics_unlocked()


def record_captured_event() -> None:
    """Increment total only when packet is captured (before AI)."""
    with _STATS_LOCK:
        _live_stats["total"] += 1
        _mirror_stats_to_memory_store_unlocked()
    _maybe_persist_statistics()


def _mirror_stats_to_memory_store_unlocked() -> None:
    from storage import memory_store

    memory_store.stats["total"] = _live_stats["total"]
    memory_store.stats["safe"] = _live_stats["safe"]
    memory_store.stats["suspicious"] = _live_stats["suspicious"]
    memory_store.stats["dangerous"] = _live_stats["dangerous"]
    memory_store.stats["unique_attackers"] = _live_stats["unique_attackers"]
    memory_store.stats["dangerous_ips"] = _live_stats["dangerous_ips"]
    memory_store.stats["dangerous_urls"] = _live_stats["dangerous_urls"]


def record_analysis_result(
    classification: str,
    *,
    src_ip: str | None = None,
    url: str | None = None,
) -> None:
    """Update safe/suspicious/dangerous only after final AI classification."""
    label = (classification or "safe").lower()
    if label not in ("safe", "suspicious", "dangerous"):
        label = "safe"

    with _STATS_LOCK:
        _live_stats[label] += 1
        if label == "dangerous" and src_ip:
            _live_stats["unique_attackers"].add(src_ip)
            _live_stats["dangerous_ips"].add(src_ip)
        if label == "dangerous" and url:
            _live_stats["dangerous_urls"].add(url)
        _mirror_stats_to_memory_store_unlocked()

    _maybe_persist_statistics()

    if label == "dangerous" and src_ip:
        upsert_dangerous_ip(src_ip)


def enqueue_packet_log(entry: dict) -> None:
    with _FLUSH_LOCK:
        _LOG_BATCH.append(entry)


def enqueue_ai_history(entry: dict) -> None:
    with _FLUSH_LOCK:
        _AI_BATCH.append(entry)


def should_enqueue_training_sample(classification: str) -> bool:
    """Decide whether a scored flow should be stored for model retraining."""
    if not _TRAINING_ENABLED:
        return False
    label = (classification or "safe").lower()
    if label in ("suspicious", "dangerous"):
        return True
    if label == "safe":
        import random

        return random.random() < _TRAINING_SAFE_RATE
    return False


def enqueue_training_sample(
    features,
    label: str,
    *,
    created_at: float | None = None,
) -> None:
    """Queue a labeled feature vector for batched insert into training_data."""
    if not should_enqueue_training_sample(label):
        return
    import numpy as np

    arr = np.asarray(features, dtype=float).ravel().tolist()
    with _FLUSH_LOCK:
        _TRAINING_BATCH.append(
            {
                "created_at": float(created_at or time.time()),
                "features_json": json.dumps(arr),
                "label": str(label).lower(),
            }
        )


def flush_batches(force: bool = False) -> int:
    """Flush pending log batches. Returns number of rows written."""
    with _FLUSH_LOCK:
        if (
            not force
            and len(_LOG_BATCH) < _BATCH_SIZE
            and len(_AI_BATCH) < _BATCH_SIZE
            and len(_TRAINING_BATCH) < _BATCH_SIZE
        ):
            return 0
        logs = list(_LOG_BATCH)
        ai_rows = list(_AI_BATCH)
        training_rows = list(_TRAINING_BATCH)
        _LOG_BATCH.clear()
        _AI_BATCH.clear()
        _TRAINING_BATCH.clear()

    written = 0
    if logs:
        written += _flush_packet_logs(logs)
    if ai_rows:
        written += _flush_ai_history(ai_rows)
    if training_rows:
        written += _flush_training_data(training_rows)
    return written


def _flush_packet_logs(entries: list[dict]) -> int:
    session = get_session()
    try:
        rows = []
        for log in entries:
            ts = resolve_event_epoch_seconds(
                packet_send_time=log.get("packet_send_time"),
                event_origin_time=log.get("event_origin_time"),
                device_timestamp=log.get("device_timestamp"),
                fallback_ingestion_time=_to_native(log.get("time")),
            )
            rows.append(
                PacketLog(
                    timestamp=ts,
                    captured_at_ms=int(round(ts * 1000)),
                    src_ip=log.get("src_ip"),
                    dst_ip=log.get("dst_ip"),
                    src_port=_to_native(log.get("src_port")),
                    dst_port=_to_native(log.get("dst_port")),
                    protocol=log.get("protocol"),
                    duration=_to_native(log.get("duration")),
                    packets=_to_native(log.get("packets")),
                    bytes=_to_native(log.get("bytes")),
                    url=log.get("url"),
                    classification=log.get("status") or log.get("classification") or "safe",
                    ai_label=log.get("ai_label"),
                    confidence=_to_native(log.get("confidence")),
                    anomaly_score=_to_native(log.get("anomaly_score")),
                    ai_score=_to_native(log.get("ai_score")),
                    risk_score=_to_native(log.get("risk_score")),
                    reasons_json=_json_dumps(log.get("reasons") or []),
                    ti_ip_json=_json_dumps(log.get("ti_ip")),
                    ti_url_json=_json_dumps(log.get("ti_url")),
                    http_json=_json_dumps(log.get("http")),
                    dns_json=_json_dumps(log.get("dns")),
                    payload_preview=log.get("payload") or log.get("payload_preview"),
                    ai_explanation_json=_json_dumps(log.get("ai_explanation")),
                )
            )
        session.add_all(rows)
        session.commit()
        return len(rows)
    except Exception:
        session.rollback()
        logger.error("Batch packet log flush failed (%d rows)", len(entries), exc_info=True)
        return 0
    finally:
        session.close()


def _flush_ai_history(entries: list[dict]) -> int:
    session = get_session()
    try:
        rows = []
        for e in entries:
            analyzed_at = e.get("analyzed_at")
            if analyzed_at is not None:
                try:
                    analyzed_dt = datetime.fromtimestamp(float(analyzed_at), tz=timezone.utc)
                except (TypeError, ValueError, OSError):
                    analyzed_dt = _utcnow()
            else:
                analyzed_dt = _utcnow()
            rows.append(
                AiAnalysisHistory(
                    analyzed_at=analyzed_dt,
                    src_ip=e.get("src_ip"),
                    dst_ip=e.get("dst_ip"),
                    classification=e.get("classification", "safe"),
                    ai_score=_to_native(e.get("ai_score")),
                    risk_score=_to_native(e.get("risk_score")),
                    rf_prob=_to_native(e.get("rf_prob")),
                    anomaly_strength=_to_native(e.get("anomaly_strength")),
                    features_json=_json_dumps(e.get("features")),
                    explanation_json=_json_dumps(e.get("explanation")),
                )
            )
        session.add_all(rows)
        session.commit()
        return len(rows)
    except Exception:
        session.rollback()
        logger.error("Batch AI history flush failed", exc_info=True)
        return 0
    finally:
        session.close()


def _flush_training_data(entries: list[dict]) -> int:
    from sqlalchemy import text

    session = get_session()
    try:
        stmt = text(
            "INSERT INTO training_data (created_at, features_json, label) "
            "VALUES (:created_at, :features_json, :label)"
        )
        session.execute(stmt, entries)
        session.commit()
        return len(entries)
    except Exception:
        session.rollback()
        logger.error("Batch training_data flush failed (%d rows)", len(entries), exc_info=True)
        return 0
    finally:
        session.close()


def writer_loop(stop_event: threading.Event | None = None) -> None:
    """Background loop: periodic batch flush."""
    while stop_event is None or not stop_event.is_set():
        try:
            flush_batches(force=True)
        except Exception:
            logger.error("Persistence writer loop error", exc_info=True)
        if stop_event and stop_event.wait(_FLUSH_INTERVAL):
            break
        elif stop_event is None:
            time.sleep(_FLUSH_INTERVAL)


def get_ti_cache(lookup_key: str, lookup_type: str) -> dict | None:
    session = get_session()
    try:
        row = session.execute(
            select(ThreatIntelCache).where(
                ThreatIntelCache.lookup_key == lookup_key,
                ThreatIntelCache.lookup_type == lookup_type,
                ThreatIntelCache.expires_at > _utcnow(),
            )
        ).scalar_one_or_none()
        if not row or not row.payload_json:
            return None
        return json.loads(row.payload_json)
    except Exception:
        return None
    finally:
        session.close()


def set_ti_cache(lookup_key: str, lookup_type: str, payload: dict, ttl_seconds: int | None = None) -> None:
    ttl = ttl_seconds or _TI_TTL_SECONDS
    now = _utcnow()
    expires = now + timedelta(seconds=ttl)
    session = get_session()
    try:
        stmt = (
            mysql_insert(ThreatIntelCache)
            .values(
                lookup_key=lookup_key,
                lookup_type=lookup_type,
                verdict=payload.get("verdict"),
                score=payload.get("score"),
                payload_json=_json_dumps(payload),
                cached_at=now,
                expires_at=expires,
            )
            .on_duplicate_key_update(
                verdict=payload.get("verdict"),
                score=payload.get("score"),
                payload_json=_json_dumps(payload),
                cached_at=now,
                expires_at=expires,
            )
        )
        session.execute(stmt)
        session.commit()
    except Exception:
        session.rollback()
        logger.debug("TI cache write failed for %s", lookup_key, exc_info=True)
    finally:
        session.close()


def upsert_dangerous_ip(ip_address: str, *, risk_score: float | None = None, reasons: list | None = None) -> None:
    now = _utcnow()
    session = get_session()
    try:
        stmt = (
            mysql_insert(DangerousIp)
            .values(
                ip_address=ip_address,
                first_seen=now,
                last_seen=now,
                event_count=1,
                max_risk_score=risk_score,
                reasons_json=_json_dumps(reasons or []),
            )
            .on_duplicate_key_update(
                last_seen=now,
                event_count=DangerousIp.event_count + 1,
                max_risk_score=func.greatest(
                    func.coalesce(DangerousIp.max_risk_score, 0),
                    risk_score or 0,
                ),
                reasons_json=_json_dumps(reasons or []),
            )
        )
        session.execute(stmt)
        session.commit()
    except Exception:
        session.rollback()
        logger.debug("Dangerous IP upsert failed for %s", ip_address, exc_info=True)
    finally:
        session.close()


def cleanup_retention() -> dict[str, int]:
    cutoff_ts = time.time() - (_RETENTION_DAYS * 86400)
    cutoff_dt = datetime.fromtimestamp(cutoff_ts, tz=timezone.utc)
    session = get_session()
    counts = {"packet_logs": 0, "ai_history": 0, "ti_cache": 0}
    try:
        r1 = session.execute(delete(PacketLog).where(PacketLog.timestamp < cutoff_ts))
        r2 = session.execute(delete(AiAnalysisHistory).where(AiAnalysisHistory.analyzed_at < cutoff_dt))
        r3 = session.execute(delete(ThreatIntelCache).where(ThreatIntelCache.expires_at < _utcnow()))
        session.commit()
        counts["packet_logs"] = int(r1.rowcount or 0)
        counts["ai_history"] = int(r2.rowcount or 0)
        counts["ti_cache"] = int(r3.rowcount or 0)
        return counts
    except Exception:
        session.rollback()
        logger.error("Retention cleanup failed", exc_info=True)
        return counts
    finally:
        session.close()


def load_statistics_for_api() -> dict[str, Any]:
    """Authoritative counters from MySQL (same values on every page refresh)."""
    session = get_session()
    try:
        row = session.get(IdsStatistics, 1)
        if row is None:
            return {
                "total": 0,
                "safe": 0,
                "suspicious": 0,
                "dangerous": 0,
                "unique_attackers": 0,
                "dangerous_ips": [],
                "dangerous_urls": [],
            }

        attackers = _json_load_set(row.unique_attackers_json)
        dangerous_ips = _json_load_set(row.dangerous_ips_json)
        dangerous_urls = _json_load_set(row.dangerous_urls_json)

        with _STATS_LOCK:
            _live_stats["total"] = int(row.total_events or 0)
            _live_stats["safe"] = int(row.safe_count or 0)
            _live_stats["suspicious"] = int(row.suspicious_count or 0)
            _live_stats["dangerous"] = int(row.dangerous_count or 0)
            _live_stats["unique_attackers"] = attackers
            _live_stats["dangerous_ips"] = dangerous_ips
            _live_stats["dangerous_urls"] = dangerous_urls

        return {
            "total": int(row.total_events or 0),
            "safe": int(row.safe_count or 0),
            "suspicious": int(row.suspicious_count or 0),
            "dangerous": int(row.dangerous_count or 0),
            "unique_attackers": len(attackers),
            "dangerous_ips": sorted(dangerous_ips),
            "dangerous_urls": sorted(dangerous_urls),
        }
    finally:
        session.close()


def apply_telemetry_stats(incoming: dict) -> None:
    """Merge sensor POST /ids/update payload into MySQL-backed counters."""
    with _STATS_LOCK:
        for key in ("total", "safe", "suspicious", "dangerous"):
            if key in incoming:
                _live_stats[key] = int(incoming[key])

        if "unique_attackers" in incoming:
            attackers = incoming.get("unique_attackers")
            if isinstance(attackers, (list, tuple, set)):
                _live_stats["unique_attackers"] = {str(x) for x in attackers}

        if "dangerous_ips" in incoming:
            ips = incoming.get("dangerous_ips")
            if isinstance(ips, (list, tuple, set)):
                _live_stats["dangerous_ips"] = {str(x) for x in ips}

        if "dangerous_urls" in incoming:
            urls = incoming.get("dangerous_urls")
            if isinstance(urls, (list, tuple, set)):
                _live_stats["dangerous_urls"] = {str(x) for x in urls}

    _persist_statistics_unlocked()


def persist_statistics_now() -> None:
    """Force immediate write of dashboard counters to MySQL."""
    _persist_statistics_unlocked()


def shutdown_persistence() -> None:
    flush_batches(force=True)
    _persist_statistics_unlocked()
    shutdown_session()
