import json
import time
from datetime import datetime, timezone

from sqlalchemy import and_, case, delete, func, or_, select

from storage.db import engine, get_session
from storage.models import AiAnalysisHistory, Base, PacketLog
from storage.migrations import run_migrations


def init_db() -> None:
    """Deprecated — use bootstrap_db.bootstrap_database()."""
    run_migrations()


def _json_dumps(value) -> str | None:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return json.dumps(str(value), ensure_ascii=False)


def save_log(log: dict) -> None:
    """Legacy single-row insert — prefer persistence.enqueue_packet_log for batching."""
    from storage.persistence import enqueue_packet_log, flush_batches

    enqueue_packet_log(log)
    flush_batches(force=True)


def _row_to_dict(r) -> dict:
    return {
        "id": r.id,
        "timestamp": r.timestamp,
        "src_ip": r.src_ip,
        "dst_ip": r.dst_ip,
        "src_port": r.src_port,
        "dst_port": r.dst_port,
        "protocol": r.protocol,
        "duration": r.duration,
        "packets": r.packets,
        "bytes": r.bytes,
        "url": r.url,
        "classification": r.classification,
        "ai_label": r.ai_label,
        "confidence": r.confidence,
        "anomaly_score": r.anomaly_score,
        "ai_score": r.ai_score,
        "risk_score": getattr(r, "risk_score", None),
        "reasons_json": r.reasons_json,
        "ti_ip_json": r.ti_ip_json,
        "ti_url_json": r.ti_url_json,
        "http_json": getattr(r, "http_json", None),
        "dns_json": r.dns_json,
        "payload_preview": getattr(r, "payload_preview", None),
        "ai_explanation_json": getattr(r, "ai_explanation_json", None),
    }


def _apply_filters(stmt, model, **filters):
    if filters.get("ip"):
        ip = filters["ip"]
        stmt = stmt.where((model.src_ip == ip) | (model.dst_ip == ip))
    if filters.get("src_ip"):
        stmt = stmt.where(model.src_ip == filters["src_ip"])
    if filters.get("dst_ip"):
        stmt = stmt.where(model.dst_ip == filters["dst_ip"])
    if filters.get("port") is not None:
        port = int(filters["port"])
        stmt = stmt.where((model.src_port == port) | (model.dst_port == port))
    if filters.get("src_port") is not None:
        stmt = stmt.where(model.src_port == int(filters["src_port"]))
    if filters.get("dst_port") is not None:
        stmt = stmt.where(model.dst_port == int(filters["dst_port"]))
    if filters.get("protocol"):
        proto = str(filters["protocol"]).strip().upper()
        stmt = stmt.where(func.upper(model.protocol) == proto)
    if filters.get("url"):
        stmt = stmt.where(model.url.like(f"%{filters['url']}%"))
    if filters.get("classification"):
        stmt = stmt.where(model.classification == filters["classification"])
    if filters.get("ai_label"):
        stmt = stmt.where(model.ai_label == filters["ai_label"])
    if filters.get("reason"):
        stmt = stmt.where(model.reasons_json.like(f"%{filters['reason']}%"))
    if filters.get("has_threat_intel"):
        want_ti = str(filters["has_threat_intel"]).lower() in ("1", "true", "yes")
        ti_present = or_(
            and_(model.ti_ip_json.isnot(None), model.ti_ip_json != ""),
            and_(model.ti_url_json.isnot(None), model.ti_url_json != ""),
        )
        stmt = stmt.where(ti_present if want_ti else ~ti_present)
    if filters.get("start_time") is not None:
        stmt = stmt.where(model.timestamp >= float(filters["start_time"]))
    if filters.get("end_time") is not None:
        stmt = stmt.where(model.timestamp <= float(filters["end_time"]))
    if filters.get("before_time") is not None:
        stmt = stmt.where(model.timestamp < float(filters["before_time"]))
    if filters.get("min_ai_score") is not None:
        min_score = float(filters["min_ai_score"])
        # NULL ai_score means "not scored yet" — include when min is 0
        if min_score > 0:
            stmt = stmt.where(model.ai_score >= min_score)
    if filters.get("max_ai_score") is not None:
        stmt = stmt.where(model.ai_score <= float(filters["max_ai_score"]))
    if filters.get("min_anomaly_score") is not None:
        stmt = stmt.where(model.anomaly_score >= float(filters["min_anomaly_score"]))
    if filters.get("max_anomaly_score") is not None:
        stmt = stmt.where(model.anomaly_score <= float(filters["max_anomaly_score"]))
    if filters.get("min_confidence") is not None:
        stmt = stmt.where(model.confidence >= float(filters["min_confidence"]))
    if filters.get("max_confidence") is not None:
        stmt = stmt.where(model.confidence <= float(filters["max_confidence"]))
    return stmt


def query_logs(
    *,
    ip: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    port: int | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    protocol: str | None = None,
    url: str | None = None,
    classification: str | None = None,
    ai_label: str | None = None,
    reason: str | None = None,
    has_threat_intel: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    min_ai_score: float | None = None,
    max_ai_score: float | None = None,
    min_anomaly_score: float | None = None,
    max_anomaly_score: float | None = None,
    min_confidence: float | None = None,
    max_confidence: float | None = None,
    before_time: float | None = None,
    limit: int = 200,
) -> list[dict]:
    session = get_session()
    filters = dict(
        ip=ip,
        src_ip=src_ip,
        dst_ip=dst_ip,
        port=port,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        url=url,
        classification=classification,
        ai_label=ai_label,
        reason=reason,
        has_threat_intel=has_threat_intel,
        start_time=start_time,
        end_time=end_time,
        min_ai_score=min_ai_score,
        max_ai_score=max_ai_score,
        min_anomaly_score=min_anomaly_score,
        max_anomaly_score=max_anomaly_score,
        min_confidence=min_confidence,
        max_confidence=max_confidence,
        before_time=before_time,
    )
    safe_limit = max(1, min(int(limit), 2000))
    try:
        stmt = select(PacketLog)
        stmt = _apply_filters(stmt, PacketLog, **filters)
        stmt = stmt.order_by(PacketLog.timestamp.desc(), PacketLog.id.desc()).limit(safe_limit)
        rows = session.execute(stmt).scalars().all()
        return [_row_to_dict(r) for r in rows]
    finally:
        session.close()


def aggregate_log_stats(
    *,
    start_time: float | None = None,
    end_time: float | None = None,
) -> dict:
    session = get_session()
    try:
        stmt = select(PacketLog.classification, PacketLog.src_ip)
        if start_time is not None:
            stmt = stmt.where(PacketLog.timestamp >= float(start_time))
        if end_time is not None:
            stmt = stmt.where(PacketLog.timestamp <= float(end_time))

        rows = session.execute(stmt).all()

        totals = {"total": 0, "safe": 0, "suspicious": 0, "dangerous": 0}
        unique_attackers: set[str] = set()
        dangerous_ips: set[str] = set()

        for classification, src_ip in rows:
            totals["total"] += 1
            label = (classification or "safe").lower()
            if label in totals:
                totals[label] += 1
            else:
                totals["safe"] += 1
            if label == "dangerous" and src_ip:
                unique_attackers.add(src_ip)
                dangerous_ips.add(src_ip)

        return {
            **totals,
            "unique_attackers": len(unique_attackers),
            "dangerous_ips": sorted(dangerous_ips),
        }
    finally:
        session.close()


def _empty_minute_buckets(
    start_time: float,
    end_time: float,
    minutes: int,
) -> dict[int, dict]:
    bucket_start = int(start_time // 60) * 60
    bucket_end = int(end_time // 60) * 60
    buckets: dict[int, dict] = {}
    span = max(1, min(int(minutes), int((end_time - start_time) // 60) + 1))
    for i in range(span):
        key = bucket_start + i * 60
        if key > bucket_end:
            break
        buckets[key] = {
            "safe": 0,
            "suspicious": 0,
            "dangerous": 0,
            "total": 0,
            "score_sum": 0.0,
            "score_count": 0,
        }
    return buckets


def _apply_timeseries_rows(
    buckets: dict[int, dict],
    rows: list,
) -> bool:
    found = False
    for bucket, classification, cnt, avg_score in rows:
        key = int(bucket)
        if key not in buckets:
            buckets[key] = {
                "safe": 0,
                "suspicious": 0,
                "dangerous": 0,
                "total": 0,
                "score_sum": 0.0,
                "score_count": 0,
            }
        found = True
        label = (classification or "safe").lower()
        if label not in ("safe", "suspicious", "dangerous"):
            label = "safe"
        count = int(cnt or 0)
        buckets[key][label] += count
        buckets[key]["total"] += count
        if count > 0:
            score = float(avg_score or 0.0)
            buckets[key]["score_sum"] += score * count
            buckets[key]["score_count"] += count
    return found


def aggregate_traffic_timeseries(
    *,
    start_time: float | None = None,
    end_time: float | None = None,
    minutes: int = 60,
) -> dict:
    """
    Per-minute severity counts and average scores for dashboard charts.

    Uses ai_analysis_history (all classifications, including safe) with
    packet_logs as fallback when history is empty.
    """
    now = time.time()
    end_time = float(end_time if end_time is not None else now)
    start_time = float(start_time if start_time is not None else end_time - minutes * 60)
    safe_minutes = max(1, min(int(minutes), 1440))

    buckets = _empty_minute_buckets(start_time, end_time, safe_minutes)
    start_dt = datetime.fromtimestamp(start_time, tz=timezone.utc)
    end_dt = datetime.fromtimestamp(end_time, tz=timezone.utc)

    session = get_session()
    try:
        ai_bucket = (func.floor(func.unix_timestamp(AiAnalysisHistory.analyzed_at) / 60) * 60).label(
            "bucket"
        )
        trend_score = func.coalesce(
            AiAnalysisHistory.ai_score,
            AiAnalysisHistory.risk_score,
            case(
                (AiAnalysisHistory.classification == "dangerous", 0.9),
                (AiAnalysisHistory.classification == "suspicious", 0.55),
                else_=0.08,
            ),
        )
        ai_stmt = (
            select(
                ai_bucket,
                AiAnalysisHistory.classification,
                func.count().label("cnt"),
                func.avg(trend_score).label("avg_score"),
            )
            .where(AiAnalysisHistory.analyzed_at >= start_dt)
            .where(AiAnalysisHistory.analyzed_at <= end_dt)
            .group_by(ai_bucket, AiAnalysisHistory.classification)
        )
        ai_rows = session.execute(ai_stmt).all()
        has_data = _apply_timeseries_rows(buckets, ai_rows)

        if not has_data:
            log_bucket = (func.floor(PacketLog.timestamp / 60) * 60).label("bucket")
            log_score = func.coalesce(
                PacketLog.ai_score,
                PacketLog.risk_score,
                case(
                    (PacketLog.classification == "dangerous", 0.9),
                    (PacketLog.classification == "suspicious", 0.55),
                    else_=0.08,
                ),
            )
            log_stmt = (
                select(
                    log_bucket,
                    PacketLog.classification,
                    func.count().label("cnt"),
                    func.avg(log_score).label("avg_score"),
                )
                .where(PacketLog.timestamp >= start_time)
                .where(PacketLog.timestamp <= end_time)
                .group_by(log_bucket, PacketLog.classification)
            )
            log_rows = session.execute(log_stmt).all()
            has_data = _apply_timeseries_rows(buckets, log_rows)
    finally:
        session.close()

    ordered = sorted(buckets.items())
    labels: list[str] = []
    safe: list[int] = []
    suspicious: list[int] = []
    dangerous: list[int] = []
    total: list[int] = []
    avg_risk: list[float] = []

    for ts, b in ordered:
        labels.append(
            datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M")
        )
        safe.append(int(b["safe"]))
        suspicious.append(int(b["suspicious"]))
        dangerous.append(int(b["dangerous"]))
        total.append(int(b["total"]))
        avg_risk.append(
            round(b["score_sum"] / b["score_count"], 4) if b["score_count"] else 0.0
        )

    totals = {
        "safe": sum(safe),
        "suspicious": sum(suspicious),
        "dangerous": sum(dangerous),
        "total": sum(total),
    }

    return {
        "labels": labels,
        "safe": safe,
        "suspicious": suspicious,
        "dangerous": dangerous,
        "total": total,
        "avg_risk": avg_risk,
        "totals": totals,
        "start_time": start_time,
        "end_time": end_time,
        "has_data": has_data,
    }


def cleanup_old_logs(days: int = 7) -> int:
    from storage.persistence import cleanup_retention

    result = cleanup_retention()
    return int(result.get("packet_logs", 0))
