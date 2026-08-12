from datetime import datetime, timedelta, timezone

from app.db.models import CheckHistory, EmailCheckHistory, PhoneCheckHistory, url_hash
from app.db.retention import purge_expired_history
from app.db.session import SessionLocal


def _old_url_row(days_old: int) -> CheckHistory:
    return CheckHistory(
        url_hash=url_hash(f"https://retention-test-{days_old}.example"),
        url=f"https://retention-test-{days_old}.example",
        verdict="safe",
        confidence=0.9,
        model_version="test",
        checked_at=datetime.now(timezone.utc) - timedelta(days=days_old),
    )


def _old_email_row(days_old: int) -> EmailCheckHistory:
    return EmailCheckHistory(
        domain_hash=url_hash(f"retention-test-{days_old}.example"),
        domain=f"retention-test-{days_old}.example",
        verdict="safe",
        score=0,
        confidence=0.9,
        scorer_version="test",
        checked_at=datetime.now(timezone.utc) - timedelta(days=days_old),
    )


def _old_phone_row(days_old: int) -> PhoneCheckHistory:
    return PhoneCheckHistory(
        number_hash=url_hash(f"+1555000{days_old:04d}"),
        e164=f"+1555000{days_old:04d}",
        verdict="safe",
        confidence=0.5,
        scorer_version="test",
        checked_at=datetime.now(timezone.utc) - timedelta(days=days_old),
    )


def test_purge_deletes_rows_older_than_retention_window_only():
    session = SessionLocal()
    try:
        old = _old_url_row(days_old=100)
        recent = _old_url_row(days_old=1)
        session.add_all([old, recent])
        session.commit()
        old_id, recent_id = old.id, recent.id
    finally:
        session.close()

    deleted = purge_expired_history(retention_days=30)
    assert deleted["check_history"] >= 1

    session = SessionLocal()
    try:
        remaining_ids = {row.id for row in session.query(CheckHistory.id).all()}
        assert old_id not in remaining_ids
        assert recent_id in remaining_ids
    finally:
        session.query(CheckHistory).filter(CheckHistory.id == recent_id).delete()
        session.commit()
        session.close()


def test_purge_covers_email_and_phone_history_too():
    session = SessionLocal()
    try:
        old_email = _old_email_row(days_old=100)
        old_phone = _old_phone_row(days_old=100)
        session.add_all([old_email, old_phone])
        session.commit()
        old_email_id, old_phone_id = old_email.id, old_phone.id
    finally:
        session.close()

    purge_expired_history(retention_days=30)

    session = SessionLocal()
    try:
        assert session.get(EmailCheckHistory, old_email_id) is None
        assert session.get(PhoneCheckHistory, old_phone_id) is None
    finally:
        session.close()


def test_purge_keeps_rows_within_retention_window():
    session = SessionLocal()
    try:
        recent = _old_url_row(days_old=5)
        session.add(recent)
        session.commit()
        recent_id = recent.id
    finally:
        session.close()

    purge_expired_history(retention_days=30)

    session = SessionLocal()
    try:
        assert session.get(CheckHistory, recent_id) is not None
    finally:
        session.query(CheckHistory).filter(CheckHistory.id == recent_id).delete()
        session.commit()
        session.close()
