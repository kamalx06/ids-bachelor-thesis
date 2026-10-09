from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="soc")

    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    totp_qr_shown: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[str | None] = mapped_column(String(64), nullable=True)

    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    email_otp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    email_otp_code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    email_otp_code_expires: Mapped[str | None] = mapped_column(String(64), nullable=True)

    avatar_path: Mapped[str | None] = mapped_column(String(512), nullable=True)


class Log(Base):
    """Legacy log table — kept for backward compatibility."""

    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[float] = mapped_column(Float, nullable=False, index=True)

    src_ip: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    protocol: Mapped[str | None] = mapped_column(Text, nullable=True)

    duration: Mapped[float | None] = mapped_column(Float, nullable=True)
    packets: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)

    classification: Mapped[str] = mapped_column(Text, nullable=False)
    ai_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    ai_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    reasons_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    ti_ip_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    ti_url_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_explanation_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class IdsStatistics(Base):
    """Singleton row for persistent dashboard counters."""

    __tablename__ = "ids_statistics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    total_events: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    safe_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suspicious_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dangerous_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_attackers_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dangerous_ips_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_attackers_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    dangerous_ips_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    dangerous_urls_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class PacketLog(Base):
    """Primary high-volume packet event store."""

    __tablename__ = "packet_logs"
    __table_args__ = (
        Index("ix_packet_logs_ts_cls", "timestamp", "classification"),
        Index("ix_packet_logs_src_ts", "src_ip", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    captured_at_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Note: index declarations here must match scripts/sql in bootstrap_db.py.
    # src_ip / dst_ip are served by composite indexes (ix_packet_logs_src_ts)
    # and dst_port by ix_packet_logs_dst_port.
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)

    duration: Mapped[float | None] = mapped_column(Float, nullable=True)
    packets: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)

    classification: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    ai_label: Mapped[str | None] = mapped_column(String(16), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    ai_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    reasons_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    ti_ip_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    ti_url_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_explanation_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class AiAnalysisHistory(Base):
    __tablename__ = "ai_analysis_history"
    # Note: index names must match the embedded SQL schema in bootstrap_db.py
    # (IDS_SCHEMA_SQL). Using index=True here would generate SQLAlchemy-default
    # names (ix_ai_analysis_history_analyzed_at) that diverge from the SQL.
    __table_args__ = (
        Index("ix_ai_history_ts", "analyzed_at"),
        Index("ix_ai_history_src", "src_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analyzed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    classification: Mapped[str] = mapped_column(String(16), nullable=False)
    ai_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    rf_prob: Mapped[float | None] = mapped_column(Float, nullable=True)
    anomaly_strength: Mapped[float | None] = mapped_column(Float, nullable=True)
    features_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"
    __table_args__ = (
        UniqueConstraint("lookup_key", "lookup_type", name="uq_ti_lookup"),
        Index("ix_ti_key", "lookup_key"),
        Index("ix_ti_expires", "expires_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lookup_key: Mapped[str] = mapped_column(String(512), nullable=False)
    lookup_type: Mapped[str] = mapped_column(String(16), nullable=False)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    payload_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    cached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DangerousIp(Base):
    __tablename__ = "dangerous_ips"
    __table_args__ = (
        UniqueConstraint("ip_address", name="uq_dangerous_ip"),
        Index("ix_dangerous_ip", "ip_address"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    max_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    reasons_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class ThreatPattern(Base):
    """
    Aggregated suspicious/dangerous events, bucketed by hour/day/week/month
    and keyed by (src_ip, host, threat_category). Populated by the hourly
    analytics worker from packet_logs. Idempotent — the worker deletes and
    re-inserts each bucket range, so re-running is safe.
    """
    __tablename__ = "threat_patterns"
    __table_args__ = (
        Index("ix_tp_bucket", "bucket_type", "bucket_start"),
        Index("ix_tp_ip", "src_ip", "bucket_start"),
        Index("ix_tp_host", "host", "bucket_start"),
        Index("ix_tp_category", "threat_category", "bucket_start"),
        Index("ix_tp_lookup", "bucket_type", "src_ip", "host", "threat_category"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    bucket_type: Mapped[str] = mapped_column(String(16), nullable=False)
    bucket_start: Mapped[float] = mapped_column(Float, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    threat_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dangerous_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suspicious_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )