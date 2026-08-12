"""Automatic deletion of old check-history rows. People paste sensitive
things into these checkers -- password-reset links, session-bearing URLs,
phone numbers -- and there was previously no limit on how long that sat in
the database. `cache_ttl_hours` only controls when a row stops being served
from cache; it says nothing about how long the row itself persists. This
module is the actual data-retention policy: anything older than
`settings.history_retention_days` gets deleted outright, run once at
startup (see app/main.py's lifespan) rather than needing a separate
scheduler process.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from app.config import settings
from app.db.models import CheckHistory, EmailCheckHistory, PhoneCheckHistory
from app.db.session import SessionLocal


def purge_expired_history(retention_days: int | None = None) -> dict[str, int]:
    """Deletes rows older than the retention window from all three history
    tables. Returns the number of rows deleted per table, mainly so this is
    easy to unit test and to log from callers that care.
    """
    days = retention_days if retention_days is not None else settings.history_retention_days
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    deleted: dict[str, int] = {}
    session = SessionLocal()
    try:
        for table in (CheckHistory, EmailCheckHistory, PhoneCheckHistory):
            result = session.execute(delete(table).where(table.checked_at < cutoff))
            deleted[table.__tablename__] = result.rowcount
        session.commit()
    finally:
        session.close()
    return deleted
