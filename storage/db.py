import os

import dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

dotenv.load_dotenv()


def _build_database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if url:
        return url

    host = os.environ.get("MYSQL_HOST", "127.0.0.1")
    port = os.environ.get("MYSQL_PORT", "3306")
    user = os.environ.get("MYSQL_USER", "root")
    password = os.environ.get("MYSQL_PASSWORD", "")
    db = os.environ.get("MYSQL_DB", "ids_db")
    return f"mysql+pymysql://{user}:{password}@{host}:{port}/{db}?charset=utf8mb4"


DATABASE_URL = _build_database_url()

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=1800,
    pool_size=int(os.environ.get("DB_POOL_SIZE", "5") or "5"),
    max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "10") or "10"),
    future=True,
)

SessionLocal = scoped_session(
    sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
)


def get_session():
    return SessionLocal()


def shutdown_session():
    try:
        SessionLocal.remove()
    except Exception:
        pass

