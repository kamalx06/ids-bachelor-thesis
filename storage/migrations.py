from __future__ import annotations

from logging_config import get_logger
from storage.db import engine
from storage.models import Base

logger = get_logger(__name__)

_LEGACY_LOG_COLUMNS = (
    ("risk_score", "FLOAT NULL"),
    ("ai_explanation_json", "TEXT NULL"),
)


def run_migrations() -> None:
    Base.metadata.create_all(bind=engine)
    _migrate_legacy_logs_table()
    _migrate_packet_logs_bigint()
    logger.info("Database migrations applied")


def _migrate_packet_logs_bigint() -> None:
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql(
                "ALTER TABLE packet_logs MODIFY COLUMN captured_at_ms BIGINT NULL"
            )
            conn.commit()
    except Exception as exc:
        logger.debug("packet_logs captured_at_ms migration skipped: %s", exc)


def _migrate_legacy_logs_table() -> None:
    try:
        with engine.connect() as conn:
            for col_name, col_def in _LEGACY_LOG_COLUMNS:
                try:
                    conn.exec_driver_sql(
                        f"ALTER TABLE logs ADD COLUMN {col_name} {col_def}"
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
    except Exception as exc:
        logger.debug("Legacy logs migration skipped: %s", exc)
