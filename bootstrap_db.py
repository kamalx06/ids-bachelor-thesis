from __future__ import annotations

import os
import re
import sys
from contextlib import contextmanager
from pathlib import Path

from logging_config import get_logger

logger = get_logger(__name__)

ROOT = Path(__file__).resolve().parent
_BOOTSTRAP_DONE = False
_DB_NAME_RE = re.compile(r"[A-Za-z0-9_]+")

# ---------------------------------------------------------------------------
# IDS MySQL schema (formerly scripts/sql/migrate_ids_schema.sql)
# Compatible with MariaDB / MySQL 8+.
# ---------------------------------------------------------------------------
IDS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ids_statistics (
    id INT PRIMARY KEY DEFAULT 1,
    total_events BIGINT NOT NULL DEFAULT 0,
    safe_count BIGINT NOT NULL DEFAULT 0,
    suspicious_count BIGINT NOT NULL DEFAULT 0,
    dangerous_count BIGINT NOT NULL DEFAULT 0,
    unique_attackers_count INT NOT NULL DEFAULT 0,
    dangerous_ips_count INT NOT NULL DEFAULT 0,
    unique_attackers_json LONGTEXT NULL,
    dangerous_ips_json LONGTEXT NULL,
    dangerous_urls_json LONGTEXT NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO ids_statistics (id) VALUES (1);

CREATE TABLE IF NOT EXISTS packet_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DOUBLE NOT NULL,
    captured_at_ms BIGINT NULL,
    src_ip VARCHAR(45) NULL,
    dst_ip VARCHAR(45) NULL,
    src_port INT NULL,
    dst_port INT NULL,
    protocol VARCHAR(16) NULL,
    duration DOUBLE NULL,
    packets INT NULL,
    bytes INT NULL,
    url TEXT NULL,
    classification VARCHAR(16) NOT NULL,
    ai_label VARCHAR(16) NULL,
    confidence DOUBLE NULL,
    anomaly_score DOUBLE NULL,
    ai_score DOUBLE NULL,
    risk_score DOUBLE NULL,
    reasons_json LONGTEXT NULL,
    ti_ip_json LONGTEXT NULL,
    ti_url_json LONGTEXT NULL,
    http_json LONGTEXT NULL,
    dns_json LONGTEXT NULL,
    payload_preview TEXT NULL,
    ai_explanation_json LONGTEXT NULL,
    INDEX ix_packet_logs_timestamp (timestamp),
    INDEX ix_packet_logs_ts_cls (timestamp, classification),
    INDEX ix_packet_logs_src_ts (src_ip, timestamp),
    INDEX ix_packet_logs_classification (classification),
    INDEX ix_packet_logs_dst_port (dst_port)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ai_analysis_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    analyzed_at DATETIME(6) NOT NULL,
    src_ip VARCHAR(45) NULL,
    dst_ip VARCHAR(45) NULL,
    classification VARCHAR(16) NOT NULL,
    ai_score DOUBLE NULL,
    risk_score DOUBLE NULL,
    rf_prob DOUBLE NULL,
    anomaly_strength DOUBLE NULL,
    features_json LONGTEXT NULL,
    explanation_json LONGTEXT NULL,
    INDEX ix_ai_history_ts (analyzed_at),
    INDEX ix_ai_history_src (src_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    lookup_key VARCHAR(512) NOT NULL,
    lookup_type VARCHAR(16) NOT NULL,
    verdict VARCHAR(32) NULL,
    score DOUBLE NULL,
    payload_json LONGTEXT NULL,
    cached_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    UNIQUE KEY uq_ti_lookup (lookup_key, lookup_type),
    INDEX ix_ti_expires (expires_at),
    INDEX ix_ti_key (lookup_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dangerous_ips (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    event_count INT NOT NULL DEFAULT 1,
    max_risk_score DOUBLE NULL,
    reasons_json LONGTEXT NULL,
    UNIQUE KEY uq_dangerous_ip (ip_address),
    INDEX ix_dangerous_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS training_data (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    created_at DOUBLE NOT NULL,
    features_json LONGTEXT NOT NULL,
    label VARCHAR(32) NOT NULL,
    INDEX ix_training_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS threat_patterns (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    bucket_type VARCHAR(16) NOT NULL,
    bucket_start DOUBLE NOT NULL,
    src_ip VARCHAR(45) NULL,
    host VARCHAR(255) NULL,
    threat_category VARCHAR(64) NULL,
    event_count INT NOT NULL DEFAULT 0,
    dangerous_count INT NOT NULL DEFAULT 0,
    suspicious_count INT NOT NULL DEFAULT 0,
    max_risk_score DOUBLE NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX ix_tp_bucket (bucket_type, bucket_start),
    INDEX ix_tp_ip (src_ip, bucket_start),
    INDEX ix_tp_host (host, bucket_start),
    INDEX ix_tp_category (threat_category, bucket_start),
    INDEX ix_tp_lookup (bucket_type, src_ip, host, threat_category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ssl_config (
    id INT PRIMARY KEY DEFAULT 1,
    ca_common_name VARCHAR(255) NOT NULL,
    ca_serial_hex VARCHAR(64) NULL,
    ca_not_before DATETIME(6) NULL,
    ca_not_after DATETIME(6) NULL,
    ca_fingerprint_sha256 VARCHAR(128) NULL,
    ca_created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO ssl_config (id, ca_common_name) VALUES (1, 'Enterprise AI IDS Root CA');

CREATE TABLE IF NOT EXISTS ssl_bypass_rules (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    match_type VARCHAR(16) NOT NULL,
    pattern VARCHAR(255) NOT NULL,
    reason VARCHAR(255) NULL,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_ssl_bypass (match_type, pattern),
    INDEX ix_ssl_bypass_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def _run_sql(connection, sql: str, *, label: str = "schema", strict: bool = True) -> None:
    """
    Execute a raw SQL blob statement-by-statement.

    Splitting on ';' is fine for the current DDL. If you later add triggers
    or stored procedures containing ';', pass a pre-parsed statement list
    instead.
    """
    statements = [stmt for raw in sql.split(";") if (stmt := raw.strip())]
    errors: list[tuple[str, Exception]] = []

    with connection.cursor() as cur:
        for stmt in statements:
            try:
                cur.execute(stmt)
            except Exception as exc:
                logger.warning(
                    "SQL statement failed in %s: %s -- %s",
                    label,
                    exc,
                    stmt[:200],
                )
                errors.append((stmt, exc))

    if strict and errors:
        raise RuntimeError(f"{len(errors)} SQL statement(s) failed in {label}")


@contextmanager
def _db_session():
    """
    SQLAlchemy session that commits on a clean exit, rolls back and
    re-raises on error, and always closes -- shared by the small "seed a
    row if missing" bootstrap steps below so each one only has to state its
    own query/insert, not repeat the session lifecycle around it.
    """
    from storage.db import get_session

    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _load_env() -> bool:
    try:
        from dotenv import load_dotenv

        env_path = ROOT / ".env"
        if env_path.exists():
            load_dotenv(str(env_path), override=False)
            return True
    except Exception:
        return False
    return False


def _get_mysql_env() -> dict:
    return {
        "host": os.environ.get("MYSQL_HOST", "127.0.0.1"),
        "port": int(os.environ.get("MYSQL_PORT", "3306") or "3306"),
        "user": os.environ.get("MYSQL_USER", "root"),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "db": os.environ.get("MYSQL_DB", "ids_db"),
    }


def _validate_db_name(db: str) -> bool:
    return bool(_DB_NAME_RE.fullmatch(db or ""))


def _bootstrap_mysql_database() -> bool:
    """Create MySQL database and apply the embedded schema."""
    mysql_cfg = _get_mysql_env()
    if not _validate_db_name(mysql_cfg["db"]):
        logger.error("Invalid MySQL database name: %s", mysql_cfg["db"])
        return False

    try:
        import pymysql

        connection = pymysql.connect(
            host=mysql_cfg["host"],
            port=mysql_cfg["port"],
            user=mysql_cfg["user"],
            password=mysql_cfg["password"],
            autocommit=True,
        )
        try:
            with connection.cursor() as cur:
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{mysql_cfg['db']}` "
                    "DEFAULT CHARACTER SET utf8mb4;"
                )
                connection.select_db(mysql_cfg["db"])

            logger.info("Applying embedded IDS MySQL schema")
            _run_sql(connection, IDS_SCHEMA_SQL, label="IDS_SCHEMA_SQL")
        finally:
            connection.close()
        return True
    except Exception as exc:
        logger.warning("MySQL bootstrap skipped or failed: %s", exc)
        return False


def _bootstrap_sqlalchemy_schema() -> None:
    root_str = str(ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    from storage.migrations import run_migrations

    run_migrations()


def _ensure_ids_statistics_row() -> None:
    from sqlalchemy import select

    from storage.models import IdsStatistics

    try:
        with _db_session() as session:
            row = session.execute(
                select(IdsStatistics).where(IdsStatistics.id == 1)
            ).scalar_one_or_none()
            if row is None:
                session.add(IdsStatistics(id=1))
                logger.info("Initialized ids_statistics singleton row")
    except Exception as exc:
        logger.debug("ids_statistics seed skipped: %s", exc)


def _ensure_default_admin() -> None:
    """
    Create bootstrap admin only when no users exist and env credentials are set.
    """
    username = (os.environ.get("IDS_BOOTSTRAP_ADMIN_USER") or "").strip()
    password = (os.environ.get("IDS_BOOTSTRAP_ADMIN_PASSWORD") or "").strip()
    if not username or not password:
        return

    from argon2 import PasswordHasher
    from argon2.low_level import Type
    from sqlalchemy import func, select

    from storage.models import User

    try:
        with _db_session() as session:
            count = session.execute(select(func.count()).select_from(User)).scalar() or 0
            if count > 0:
                return

            ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, type=Type.ID)
            session.add(
                User(
                    username=username,
                    password_hash=ph.hash(password),
                    role="admin",
                )
            )
            logger.info("Bootstrap admin user created: %s", username)
    except Exception as exc:
        logger.warning("Default admin bootstrap skipped: %s", exc)


def _bootstrap_sqlite_training_store() -> None:
    """Legacy SQLite training store used by engine.sniffer (DB_PATH)."""
    try:
        from storage.persistent_store import ensure_sqlite_schema

        ensure_sqlite_schema()
    except Exception as exc:
        logger.debug("SQLite training schema bootstrap skipped: %s", exc)


def _ensure_default_ssl_bypass_rules() -> None:
    """
    Seed a conservative bypass list so certificate-pinned services
    (Apple, Google, banking) don't break on first SSL interceptor start.
    """
    from sqlalchemy import select

    from storage.models import SslBypassRule

    defaults = [
        ("sni", "*.icloud.com", "Apple services (cert-pinned)"),
        ("sni", "*.apple.com", "Apple services (cert-pinned)"),
        ("sni", "*.mzstatic.com", "Apple CDN (cert-pinned)"),
        ("sni", "*.googleapis.com", "Android GMS (cert-pinned)"),
        ("sni", "*.gstatic.com", "Google CDN"),
        ("sni", "*.mozilla.org", "Firefox updates"),
        ("sni", "*.windowsupdate.com", "Windows updates"),
        ("sni", "*.microsoft.com", "Microsoft services"),
    ]
    try:
        with _db_session() as session:
            existing = session.execute(
                select(SslBypassRule.id).limit(1)
            ).scalar_one_or_none()
            if existing is not None:
                return
            for match_type, pattern, reason in defaults:
                session.add(SslBypassRule(
                    match_type=match_type,
                    pattern=pattern,
                    reason=reason,
                    enabled=True,
                ))
            logger.info("Seeded %d default SSL bypass rules", len(defaults))
    except Exception as exc:
        logger.debug("SSL bypass seed skipped: %s", exc)


def bootstrap_database(*, force: bool = False) -> int:
    """
    Full idempotent database initialization.

    Returns 0 on success, 1 on hard failure.
    """
    global _BOOTSTRAP_DONE
    if _BOOTSTRAP_DONE and not force:
        return 0

    skip = (os.environ.get("IDS_SKIP_DB_BOOTSTRAP", "false") or "false").lower() == "true"
    if skip:
        logger.info("IDS_SKIP_DB_BOOTSTRAP=true — skipping database bootstrap")
        _BOOTSTRAP_DONE = True
        return 0

    env_loaded = _load_env()
    if not env_loaded and "MYSQL_HOST" not in os.environ and "MYSQL_DB" not in os.environ:
        logger.info("No .env / MYSQL_* — running SQLAlchemy-only bootstrap where possible")

    _bootstrap_mysql_database()
    try:
        _bootstrap_sqlalchemy_schema()
        _ensure_ids_statistics_row()
        _ensure_default_admin()
        _bootstrap_sqlite_training_store()
        _ensure_default_ssl_bypass_rules()
    except Exception as exc:
        logger.error("Schema bootstrap failed: %s", exc, exc_info=True)
        return 1

    _BOOTSTRAP_DONE = True
    logger.info("Database bootstrap completed")
    return 0


# Backward-compatible alias used by setup.py
def bootstrap_mysql_schema() -> int:
    return bootstrap_database()


if __name__ == "__main__":
    raise SystemExit(bootstrap_database())