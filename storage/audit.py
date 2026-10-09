"""
Audit log helper. Every privileged action calls audit() and lands in
audit_log. Reads are exposed through /audit/api/entries.

Design notes:
- Failures to write the audit row are swallowed (logged) rather than
  propagated. An audit backend outage should never break the login flow
  or an admin action that otherwise succeeded.
- actor_id/actor_username are filled from current_user when available.
  For pre-auth events (login attempts), callers pass actor_username
  explicitly.
- actor_ip is taken from request.remote_addr, honoring ProxyFix if
  TRUSTED_PROXIES is configured.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select

from logging_config import get_logger
from storage.db import get_session
from storage.models import AuditLog

logger = get_logger(__name__)


# Retention: keep audit rows longer than packet logs. 180 days is a
# common minimum for compliance frameworks.
_AUDIT_RETENTION_DAYS = 180


def _current_actor() -> tuple[int | None, str | None, str | None]:
    """Best-effort extraction of actor and client IP from the request."""
    actor_id = None
    actor_username = None
    actor_ip = None

    try:
        from flask import request, has_request_context
        from flask_login import current_user
        if has_request_context():
            actor_ip = request.remote_addr
            if getattr(current_user, "is_authenticated", False):
                actor_id = int(current_user.id)
                actor_username = current_user.username
    except Exception:
        pass

    return actor_id, actor_username, actor_ip


def audit(
    action: str,
    *,
    target_type: str | None = None,
    target_id: str | int | None = None,
    outcome: str = "success",
    detail: dict[str, Any] | None = None,
    actor_id: int | None = None,
    actor_username: str | None = None,
    actor_ip: str | None = None,
) -> None:
    """
    Write one audit row. Never raises — audit failures are logged, not
    propagated, so a broken audit backend cannot break authentication
    or admin flows.
    """
    try:
        cur_id, cur_name, cur_ip = _current_actor()
        session = get_session()
        try:
            session.add(AuditLog(
                ts=datetime.now(timezone.utc).replace(tzinfo=None),
                actor_id=actor_id if actor_id is not None else cur_id,
                actor_username=actor_username if actor_username is not None else cur_name,
                actor_ip=actor_ip if actor_ip is not None else cur_ip,
                action=action,
                target_type=target_type,
                target_id=str(target_id) if target_id is not None else None,
                outcome=outcome,
                detail_json=_safe_json(detail),
            ))
            session.commit()
        finally:
            session.close()
    except Exception:
        logger.error("Audit write failed: action=%s outcome=%s", action, outcome, exc_info=True)


def _safe_json(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False, default=str)[:8000]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def query_audit(
    *,
    action: str | None = None,
    actor_username: str | None = None,
    target_type: str | None = None,
    outcome: str | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    before_ts: float | None = None,
    before_id: int | None = None,
    limit: int = 100,
) -> list[dict]:
    """
    Cursor-paginated query. Pass (before_ts, before_id) from the last row
    of the previous page to fetch the next page.
    """
    limit = max(1, min(int(limit), 500))
    session = get_session()
    try:
        stmt = select(AuditLog).order_by(AuditLog.ts.desc(), AuditLog.id.desc())

        if action:
            stmt = stmt.where(AuditLog.action == action)
        if actor_username:
            stmt = stmt.where(AuditLog.actor_username == actor_username)
        if target_type:
            stmt = stmt.where(AuditLog.target_type == target_type)
        if outcome:
            stmt = stmt.where(AuditLog.outcome == outcome)
        if start_time is not None:
            stmt = stmt.where(
                AuditLog.ts >= datetime.fromtimestamp(float(start_time), tz=timezone.utc).replace(tzinfo=None)
            )
        if end_time is not None:
            stmt = stmt.where(
                AuditLog.ts <= datetime.fromtimestamp(float(end_time), tz=timezone.utc).replace(tzinfo=None)
            )
        if before_ts is not None and before_id is not None:
            cutoff = datetime.fromtimestamp(float(before_ts), tz=timezone.utc).replace(tzinfo=None)
            stmt = stmt.where(
                (AuditLog.ts < cutoff)
                | ((AuditLog.ts == cutoff) & (AuditLog.id < int(before_id)))
            )

        stmt = stmt.limit(limit)
        rows = session.execute(stmt).scalars().all()

        out = []
        for r in rows:
            detail = None
            if r.detail_json:
                try:
                    detail = json.loads(r.detail_json)
                except Exception:
                    detail = {"_raw": r.detail_json[:500]}
            out.append({
                "id": r.id,
                "ts": r.ts.replace(tzinfo=timezone.utc).timestamp() if r.ts.tzinfo is None else r.ts.timestamp(),
                "actor_id": r.actor_id,
                "actor_username": r.actor_username,
                "actor_ip": r.actor_ip,
                "action": r.action,
                "target_type": r.target_type,
                "target_id": r.target_id,
                "outcome": r.outcome,
                "detail": detail,
            })
        return out
    finally:
        session.close()


def distinct_actions(limit: int = 100) -> list[str]:
    session = get_session()
    try:
        rows = session.execute(
            select(AuditLog.action).distinct().order_by(AuditLog.action.asc()).limit(limit)
        ).all()
        return [r[0] for r in rows if r[0]]
    finally:
        session.close()


def stats_since(start_time: float) -> dict:
    """Summary counts for the top of the audit page."""
    cutoff = datetime.fromtimestamp(float(start_time), tz=timezone.utc).replace(tzinfo=None)
    session = get_session()
    try:
        total = session.execute(
            select(func.count()).select_from(AuditLog).where(AuditLog.ts >= cutoff)
        ).scalar() or 0
        failures = session.execute(
            select(func.count()).select_from(AuditLog)
            .where(AuditLog.ts >= cutoff)
            .where(AuditLog.outcome != "success")
        ).scalar() or 0
        distinct_actors = session.execute(
            select(func.count(func.distinct(AuditLog.actor_username)))
            .where(AuditLog.ts >= cutoff)
            .where(AuditLog.actor_username.isnot(None))
        ).scalar() or 0
        return {
            "total": int(total),
            "failures": int(failures),
            "distinct_actors": int(distinct_actors),
        }
    finally:
        session.close()


def cleanup_retention(days: int = _AUDIT_RETENTION_DAYS) -> int:
    """Delete audit rows older than the retention window."""
    cutoff = datetime.fromtimestamp(
        time.time() - days * 86400, tz=timezone.utc
    ).replace(tzinfo=None)
    session = get_session()
    try:
        result = session.execute(delete(AuditLog).where(AuditLog.ts < cutoff))
        session.commit()
        return int(result.rowcount or 0)
    except Exception:
        session.rollback()
        logger.error("Audit retention cleanup failed", exc_info=True)
        return 0
    finally:
        session.close()