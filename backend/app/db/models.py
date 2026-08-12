from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def url_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


class CheckHistory(Base):
    """One row per URL we've scored. `url_hash` (not the raw URL) is the
    lookup key for the recent-check cache -- keeps a cheap index and avoids
    ever needing to worry about URL length/encoding as a key."""

    __tablename__ = "check_history"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    url_hash: Mapped[str] = mapped_column(String(64), index=True, unique=False)
    url: Mapped[str] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(String(16))  # "safe" | "phishing"
    confidence: Mapped[float] = mapped_column(Float)
    low_confidence: Mapped[bool] = mapped_column(Boolean, default=False)
    missing_signals: Mapped[str] = mapped_column(String(128), default="")  # comma-separated
    override_reason: Mapped[str | None] = mapped_column(String(32), default=None)
    site_description: Mapped[str | None] = mapped_column(Text, default=None)
    reason_narrative: Mapped[str | None] = mapped_column(Text, default=None)
    domain_age_days: Mapped[int | None] = mapped_column(Integer, default=None)
    tls_cert_age_days: Mapped[int | None] = mapped_column(Integer, default=None)
    dns_resolves: Mapped[bool | None] = mapped_column(Boolean, default=None)
    redirect_count: Mapped[int] = mapped_column(Integer, default=0)
    safe_browsing_checked: Mapped[bool] = mapped_column(Boolean, default=False)
    virustotal_checked: Mapped[bool] = mapped_column(Boolean, default=False)
    virustotal_malicious_count: Mapped[int | None] = mapped_column(Integer, default=None)
    virustotal_total_engines: Mapped[int | None] = mapped_column(Integer, default=None)
    model_version: Mapped[str] = mapped_column(String(32))
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class EmailCheckHistory(Base):
    """One row per email sending-domain we've scored. Mirrors CheckHistory's
    shape/precedent: `domain_hash` is the cache lookup key, and only the
    expensive network-derived fields are stored -- typosquat/popularity are
    cheap and local, so the route recomputes them fresh on every request
    (including cache hits) instead of persisting them here."""

    __tablename__ = "email_check_history"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    domain_hash: Mapped[str] = mapped_column(String(64), index=True, unique=False)
    domain: Mapped[str] = mapped_column(String(255))
    verdict: Mapped[str] = mapped_column(String(16))  # "safe" | "phishing"
    score: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)
    low_confidence: Mapped[bool] = mapped_column(Boolean, default=False)
    override_reason: Mapped[str | None] = mapped_column(String(32), default=None)
    dns_resolves: Mapped[bool | None] = mapped_column(Boolean, default=None)
    mx_present: Mapped[bool | None] = mapped_column(Boolean, default=None)
    spf_present: Mapped[bool | None] = mapped_column(Boolean, default=None)
    dmarc_present: Mapped[bool | None] = mapped_column(Boolean, default=None)
    domain_age_days: Mapped[int | None] = mapped_column(Integer, default=None)
    has_valid_https: Mapped[bool | None] = mapped_column(Boolean, default=None)
    safe_browsing_checked: Mapped[bool] = mapped_column(Boolean, default=False)
    virustotal_checked: Mapped[bool] = mapped_column(Boolean, default=False)
    virustotal_malicious_count: Mapped[int | None] = mapped_column(Integer, default=None)
    virustotal_total_engines: Mapped[int | None] = mapped_column(Integer, default=None)
    scorer_version: Mapped[str] = mapped_column(String(32))
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class PhoneCheckHistory(Base):
    """One row per phone number we've checked. No TTL cache read path in
    the route (the phonenumbers library is instant/offline, nothing
    expensive to cache for latency) -- this table exists purely for the
    stats footer / check history, so every check gets an unconditional
    insert here.

    Deliberately does NOT store the user's raw input string -- only the
    normalized e164 form, which is all any legitimate debugging/analytics
    use needs. Storing both (as this table originally did) meant
    `number_hash` protected nothing, since the plaintext sat right next to
    it. Rows here are subject to the same automatic retention deletion as
    the other two history tables (see app/db/retention.py) -- a phone
    number is directly identifying PII, and there's no reason to keep it
    around past the window it's actually useful for.
    """

    __tablename__ = "phone_check_history"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    number_hash: Mapped[str] = mapped_column(String(64), index=True, unique=False)
    e164: Mapped[str | None] = mapped_column(String(20), default=None)
    region_code: Mapped[str | None] = mapped_column(String(8), default=None)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    is_possible: Mapped[bool] = mapped_column(Boolean, default=False)
    line_type: Mapped[str | None] = mapped_column(String(24), default=None)
    carrier_name: Mapped[str | None] = mapped_column(String(128), default=None)
    verdict: Mapped[str] = mapped_column(String(16))  # "safe" | "phishing"
    confidence: Mapped[float] = mapped_column(Float)
    low_confidence: Mapped[bool] = mapped_column(Boolean, default=False)
    override_reason: Mapped[str | None] = mapped_column(String(32), default=None)
    scorer_version: Mapped[str] = mapped_column(String(32))
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
