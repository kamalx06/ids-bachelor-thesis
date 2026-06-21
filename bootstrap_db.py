from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from logging_config import get_logger

logger = get_logger(__name__)

ROOT = Path(__file__).resolve().parent
_BOOTSTRAP_DONE = False


def _run_sql_file(connection, file_path: Path) -> None:
    if not file_path.exists():
        logger.warning("SQL file not found: %s", file_path)
        return

    sql = file_path.read_text(encoding="utf-8")
    statements = [s.strip() for s in sql.split(";") if s.strip()]

    with connection.cursor() as cur:
        for stmt in statements:
            cur.execute(stmt)


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
    return bool(re.fullmatch(r"[A-Za-z0-9_]+", db or ""))


def _bootstrap_mysql_database() -> bool:
    """Create MySQL database and apply raw SQL migrations."""
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

            migration_file = ROOT / "scripts" / "sql" / "migrate_ids_schema.sql"
            logger.info("Applying SQL migration: %s", migration_file)
            _run_sql_file(connection, migration_file)
        finally:
            connection.close()
        return True
    except Exception as exc:
        logger.warning("MySQL bootstrap skipped or failed: %s", exc)
        return False


def _bootstrap_sqlalchemy_schema() -> None:
    sys.path.insert(0, str(ROOT))
    from storage.migrations import run_migrations

    run_migrations()


def _ensure_ids_statistics_row() -> None:
    from sqlalchemy import select

    from storage.db import get_session
    from storage.models import IdsStatistics

    session = get_session()
    try:
        row = session.execute(select(IdsStatistics).where(IdsStatistics.id == 1)).scalar_one_or_none()
        if row is None:
            session.add(IdsStatistics(id=1))
            session.commit()
            logger.info("Initialized ids_statistics singleton row")
    except Exception as exc:
        session.rollback()
        logger.debug("ids_statistics seed skipped: %s", exc)
    finally:
        session.close()


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

    from storage.db import get_session
    from storage.models import User

    session = get_session()
    try:
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
        session.commit()
        logger.info("Bootstrap admin user created: %s", username)
    except Exception as exc:
        session.rollback()
        logger.warning("Default admin bootstrap skipped: %s", exc)
    finally:
        session.close()


def _bootstrap_sqlite_training_store() -> None:
    """Legacy SQLite training store used by engine.sniffer (DB_PATH)."""
    try:
        from storage.persistent_store import ensure_sqlite_schema

        ensure_sqlite_schema()
    except Exception as exc:
        logger.debug("SQLite training schema bootstrap skipped: %s", exc)


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
