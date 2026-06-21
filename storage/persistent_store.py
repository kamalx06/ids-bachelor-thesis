import json
import os
import sqlite3
import time
from threading import Lock

import dotenv

dotenv.load_dotenv()

lock = Lock()

DB_PATH = os.environ.get("DB_PATH", "ids.db")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


_sqlite_initialized = False


def ensure_sqlite_schema() -> None:
    """Idempotent SQLite schema for legacy training samples (called from bootstrap_db)."""
    global _sqlite_initialized
    if _sqlite_initialized:
        return
    with lock:
        if _sqlite_initialized:
            return
        conn = get_conn()
        c = conn.cursor()

        c.execute(
            """
            CREATE TABLE IF NOT EXISTS training_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                features_json TEXT NOT NULL,
                label TEXT NOT NULL
            )
            """
        )

        # Drop unused legacy logs table (MySQL packet_logs is the primary store)
        c.execute("DROP TABLE IF EXISTS logs")

        conn.commit()
        conn.close()
        _sqlite_initialized = True


def init_db() -> None:
    """Backward-compatible alias."""
    ensure_sqlite_schema()


def save_training_data(features, label: str) -> None:
    """Persist a live feature vector into training_data (MySQL + SQLite)."""
    from storage import persistence

    persistence.enqueue_training_sample(features, label)
    persistence.flush_batches(force=True)

    # Keep SQLite copy for offline / legacy tooling
    import numpy as np

    arr = np.asarray(features, dtype=float).ravel().tolist()
    with lock:
        ensure_sqlite_schema()
        conn = get_conn()
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO training_data (created_at, features_json, label)
            VALUES (?, ?, ?)
            """,
            (time.time(), json.dumps(arr), str(label)),
        )
        conn.commit()
        conn.close()
