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
