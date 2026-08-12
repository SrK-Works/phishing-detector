from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import EmailCheckHistory, url_hash
from app.db.session import get_session
from app.email_verdict import resolve_email_verdict
from app.features.email_checks import extract_domain, extract_email_domain_features
from app.features.lexical import (
    brand_display_name,
    known_brand_slug,
    looks_like_url,
    typosquat_target,
)
from app.features.popularity import popularity_rank
from app.features.reputation import check_safe_browsing, check_virustotal
from app.rate_limit import limiter

SCORER_VERSION = "email-v1"

router = APIRouter()


class EmailCheckRequest(BaseModel):
    email: str = Field(min_length=1, max_length=320)


class EmailCheckResponse(BaseModel):
    domain: str
    verdict: str
    confidence: float
    low_confidence: bool
    score: int
    override_reason: str | None
    is_exact_brand_domain: bool
    known_brand_display_name: str | None
    typosquat_target: str | None
    typosquat_brand_display: str | None
    typosquat_real_domain: str | None
    typosquat_diff: str | None
    popularity_rank: int | None
    dns_resolves: bool | None
    mx_present: bool | None
    spf_present: bool | None
    dmarc_present: bool | None
    domain_age_days: int | None
    has_valid_https: bool | None
    safe_browsing_available: bool
    safe_browsing_checked: bool
    virustotal_available: bool
    virustotal_checked: bool
    virustotal_malicious_count: int | None
    virustotal_total_engines: int | None
    cached: bool


@router.post("/api/check-email", response_model=EmailCheckResponse)
@limiter.limit(settings.check_rate_limit)
def check_email(
    request: Request, payload: EmailCheckRequest, session: Session = Depends(get_session)
) -> EmailCheckResponse:
    if looks_like_url(payload.email):
        raise HTTPException(
            status_code=422,
            detail="This looks like a full URL, not an email address -- try the URL tab instead.",
        )

    domain = extract_domain(payload.email)
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="email must contain a valid domain")

    url = f"https://{domain}"
    typosquat_match = typosquat_target(url)
    brand_slug = known_brand_slug(url)
    is_exact_brand = brand_slug is not None
    known_brand_name = brand_display_name(brand_slug) if brand_slug else None
    typosquat_brand_display = brand_display_name(typosquat_match.brand) if typosquat_match else None
    rank = popularity_rank(url)
    safe_browsing_available = settings.safe_browsing_api_key is not None
    virustotal_available = settings.virustotal_api_key is not None

    digest = url_hash(domain)
    cache_cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.cache_ttl_hours)
    cached_row = session.execute(
        select(EmailCheckHistory)
        .where(EmailCheckHistory.domain_hash == digest, EmailCheckHistory.checked_at >= cache_cutoff)
        .order_by(EmailCheckHistory.checked_at.desc())
    ).scalars().first()

    if cached_row is not None:
        return EmailCheckResponse(
            domain=domain,
            verdict=cached_row.verdict,
            confidence=cached_row.confidence,
            low_confidence=cached_row.low_confidence,
            score=cached_row.score,
            override_reason=cached_row.override_reason,
            is_exact_brand_domain=is_exact_brand,
            known_brand_display_name=known_brand_name,
            typosquat_target=typosquat_match.brand if typosquat_match else None,
            typosquat_brand_display=typosquat_brand_display,
            typosquat_real_domain=typosquat_match.real_domain if typosquat_match else None,
            typosquat_diff=typosquat_match.diff_description if typosquat_match else None,
            popularity_rank=rank,
            dns_resolves=cached_row.dns_resolves,
            mx_present=cached_row.mx_present,
            spf_present=cached_row.spf_present,
            dmarc_present=cached_row.dmarc_present,
            domain_age_days=cached_row.domain_age_days,
            has_valid_https=cached_row.has_valid_https,
            safe_browsing_available=safe_browsing_available,
            safe_browsing_checked=cached_row.safe_browsing_checked,
            virustotal_available=virustotal_available,
            virustotal_checked=cached_row.virustotal_checked,
            virustotal_malicious_count=cached_row.virustotal_malicious_count,
            virustotal_total_engines=cached_row.virustotal_total_engines,
            cached=True,
        )

    executor = ThreadPoolExecutor(max_workers=3)
    try:
        features_future = executor.submit(extract_email_domain_features, domain, settings.network_timeout_seconds)
        threat_future = executor.submit(check_safe_browsing, url, settings.network_timeout_seconds)
        virustotal_future = executor.submit(check_virustotal, url, settings.network_timeout_seconds)
        features = features_future.result()
        confirmed_threat = threat_future.result()
        virustotal_result = virustotal_future.result()
    finally:
        executor.shutdown(wait=False)

    virustotal_malicious_count = virustotal_result.malicious if virustotal_result else None

    resolved = resolve_email_verdict(
        is_exact_brand=is_exact_brand,
        typosquat_matched=typosquat_match is not None,
        confirmed_threat=confirmed_threat,
        virustotal_malicious_count=virustotal_malicious_count,
        dns_resolves=features.dns_resolves,
        mx_present=features.mx_present,
        spf_present=features.spf_present,
        dmarc_present=features.dmarc_present,
        domain_age_days=features.domain_age_days,
        popularity_rank=rank,
        has_valid_https=features.has_valid_https,
    )

    session.add(
        EmailCheckHistory(
            domain_hash=digest,
            domain=domain,
            verdict=resolved.verdict,
            score=resolved.score,
            confidence=resolved.confidence,
            low_confidence=resolved.low_confidence,
            override_reason=resolved.override_reason,
            dns_resolves=features.dns_resolves,
            mx_present=features.mx_present,
            spf_present=features.spf_present,
            dmarc_present=features.dmarc_present,
            domain_age_days=features.domain_age_days,
            has_valid_https=features.has_valid_https,
            safe_browsing_checked=confirmed_threat is not None,
            virustotal_checked=virustotal_result is not None,
            virustotal_malicious_count=virustotal_malicious_count,
            virustotal_total_engines=virustotal_result.total_engines if virustotal_result else None,
            scorer_version=SCORER_VERSION,
        )
    )
    session.commit()

    return EmailCheckResponse(
        domain=domain,
        verdict=resolved.verdict,
        confidence=resolved.confidence,
        low_confidence=resolved.low_confidence,
        score=resolved.score,
        override_reason=resolved.override_reason,
        is_exact_brand_domain=is_exact_brand,
        known_brand_display_name=known_brand_name,
        typosquat_target=typosquat_match.brand if typosquat_match else None,
        typosquat_brand_display=typosquat_brand_display,
        typosquat_real_domain=typosquat_match.real_domain if typosquat_match else None,
        typosquat_diff=typosquat_match.diff_description if typosquat_match else None,
        popularity_rank=rank,
        dns_resolves=features.dns_resolves,
        mx_present=features.mx_present,
        spf_present=features.spf_present,
        dmarc_present=features.dmarc_present,
        domain_age_days=features.domain_age_days,
        has_valid_https=features.has_valid_https,
        safe_browsing_available=safe_browsing_available,
        safe_browsing_checked=confirmed_threat is not None,
        virustotal_available=virustotal_available,
        virustotal_checked=virustotal_result is not None,
        virustotal_malicious_count=virustotal_malicious_count,
        virustotal_total_engines=virustotal_result.total_engines if virustotal_result else None,
        cached=False,
    )
