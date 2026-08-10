from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import CheckHistory, url_hash
from app.db.session import get_session
from app.features.description import generate_reason_narrative, generate_site_description
from app.features.lexical import typosquat_target
from app.features.popularity import popularity_rank
from app.features.reputation import check_safe_browsing, check_virustotal
from app.model.predict import PhishingModel
from app.pipeline import extract_all_features
from app.verdict import resolve_verdict

# Override reasons that replace the model's own verdict outright -- SHAP
# reasons for the raw ML call would contradict the shown verdict in these
# cases, so they're suppressed. "no_track_record" only softens confidence
# on an unchanged verdict, so its SHAP reasons stay relevant and shown.
VERDICT_CHANGING_OVERRIDES = {
    "confirmed_threat", "virustotal_flagged", "typosquat_lookalike", "popular_domain",
}

router = APIRouter()


@lru_cache(maxsize=1)
def get_model() -> PhishingModel:
    return PhishingModel()


class CheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class Reason(BaseModel):
    feature: str
    impact: float


class CheckResponse(BaseModel):
    url: str
    verdict: str
    confidence: float
    low_confidence: bool
    missing_signals: list[str]
    typosquat_target: str | None
    typosquat_real_domain: str | None
    typosquat_diff: str | None
    popularity_rank: int | None
    override_reason: str | None
    reasons: list[Reason]
    site_description: str | None
    reason_narrative: str | None
    domain_age_days: int | None
    tls_cert_age_days: int | None
    dns_resolves: bool | None
    redirect_count: int
    safe_browsing_available: bool
    safe_browsing_checked: bool
    virustotal_available: bool
    virustotal_checked: bool
    virustotal_malicious_count: int | None
    virustotal_total_engines: int | None
    partial: bool
    cached: bool


class StatsResponse(BaseModel):
    safe_count: int
    phishing_count: int


@router.post("/api/check", response_model=CheckResponse)
def check_url(payload: CheckRequest, session: Session = Depends(get_session)) -> CheckResponse:
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="url must not be empty")
    if "://" not in url:
        url = f"https://{url}"

    typosquat_match = typosquat_target(url)
    lookalike_of = typosquat_match.brand if typosquat_match else None
    rank = popularity_rank(url)
    # Whether a key is *configured at all*, independent of whether this
    # particular request got an answer -- always reflects current settings,
    # not stored per-check, so a key added/rotated after an old cached
    # check still reports correctly. Without this, "checked=False" alone
    # can't tell a user "no API key configured" apart from "configured, but
    # this specific call failed or got rate-limited" -- the UI used to
    # claim the former even when the latter was true.
    safe_browsing_available = settings.safe_browsing_api_key is not None
    virustotal_available = settings.virustotal_api_key is not None
    digest = url_hash(url)
    cache_cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.cache_ttl_hours)
    cached_row = session.execute(
        select(CheckHistory)
        .where(CheckHistory.url_hash == digest, CheckHistory.checked_at >= cache_cutoff)
        .order_by(CheckHistory.checked_at.desc())
    ).scalars().first()

    if cached_row is not None:
        return CheckResponse(
            url=url,
            verdict=cached_row.verdict,
            confidence=cached_row.confidence,
            low_confidence=cached_row.low_confidence,
            missing_signals=[s for s in cached_row.missing_signals.split(",") if s],
            typosquat_target=lookalike_of,
            typosquat_real_domain=typosquat_match.real_domain if typosquat_match else None,
            typosquat_diff=typosquat_match.diff_description if typosquat_match else None,
            popularity_rank=rank,
            override_reason=cached_row.override_reason,
            reasons=[],
            site_description=cached_row.site_description,
            reason_narrative=cached_row.reason_narrative,
            domain_age_days=cached_row.domain_age_days,
            tls_cert_age_days=cached_row.tls_cert_age_days,
            dns_resolves=cached_row.dns_resolves,
            redirect_count=cached_row.redirect_count,
            safe_browsing_available=safe_browsing_available,
            safe_browsing_checked=cached_row.safe_browsing_checked,
            virustotal_available=virustotal_available,
            virustotal_checked=cached_row.virustotal_checked,
            virustotal_malicious_count=cached_row.virustotal_malicious_count,
            virustotal_total_engines=cached_row.virustotal_total_engines,
            partial=False,
            cached=True,
        )

    # Run the full feature pipeline and both reputation checks concurrently
    # -- they're independent, and each is a single fixed-endpoint HTTPS call
    # so there's no reason to add their latency on top serially. All three
    # are internally self-timeout-bounded, so .result() below can't hang.
    executor = ThreadPoolExecutor(max_workers=3)
    try:
        features_future = executor.submit(extract_all_features, url)
        threat_future = executor.submit(
            check_safe_browsing, url, settings.network_timeout_seconds
        )
        virustotal_future = executor.submit(
            check_virustotal, url, settings.network_timeout_seconds
        )
        features = features_future.result()
        confirmed_threat = threat_future.result()
        virustotal_result = virustotal_future.result()
    finally:
        executor.shutdown(wait=False)

    virustotal_malicious_count = virustotal_result.malicious if virustotal_result else None

    model = get_model()
    flat_features = features.as_flat_dict()
    prediction = model.predict(flat_features)
    dns_resolves = features.host.dns_resolves if features.host else None
    resolved = resolve_verdict(
        prediction,
        popularity_rank=rank,
        confirmed_threat=confirmed_threat,
        virustotal_malicious_count=virustotal_malicious_count,
        typosquat_target=lookalike_of,
        whois_missing=features.whois_missing,
        dns_resolves=dns_resolves,
    )

    # Sequential, not concurrent with the block above: both need the page
    # title/meta/reasons that the steps above just produced. Purely
    # informational (never touch verdict/reasons themselves), so any
    # failure here just omits the text rather than affecting the response.
    site_description = generate_site_description(
        url,
        title=features.content.page_title if features.content else None,
        meta_description=features.content.meta_description if features.content else None,
        timeout=settings.network_timeout_seconds,
    )

    domain_age_days = features.host.domain_age_days if features.host else None
    tls_cert_age_days = features.host.tls_cert_age_days if features.host else None
    redirect_count = features.content.redirect_count if features.content else 0

    # Suppressed on the same overrides as `reasons` below -- a narrative
    # built from raw SHAP reasons would contradict a verdict we've already
    # overridden outright (e.g. explaining "why it's phishing" for a URL
    # we're about to show as "safe" because of its Tranco rank).
    shown_reasons = (
        []
        if resolved.override_reason in VERDICT_CHANGING_OVERRIDES
        else prediction.top_reasons
    )
    # Pairs each shown reason with its actual feature value (not just the
    # name + SHAP direction) -- without it, the narrative model has to
    # guess what a feature's value "probably" was, and can invent a
    # plausible but wrong story (see generate_reason_narrative's docstring).
    enriched_reasons = [
        (name, impact, flat_features.get(name)) for name, impact in shown_reasons
    ]
    reason_narrative = generate_reason_narrative(
        verdict=resolved.verdict,
        reasons=enriched_reasons,
        domain_age_days=domain_age_days,
        tls_cert_age_days=tls_cert_age_days,
        redirect_count=redirect_count,
        timeout=settings.network_timeout_seconds,
    )

    missing_signals = []
    if features.whois_missing:
        missing_signals.append("domain_age")
    if features.content_unavailable:
        missing_signals.append("page_content")

    session.add(
        CheckHistory(
            url_hash=digest,
            url=url,
            verdict=resolved.verdict,
            confidence=resolved.confidence,
            low_confidence=resolved.low_confidence,
            missing_signals=",".join(missing_signals),
            override_reason=resolved.override_reason,
            site_description=site_description,
            reason_narrative=reason_narrative,
            domain_age_days=domain_age_days,
            tls_cert_age_days=tls_cert_age_days,
            dns_resolves=dns_resolves,
            redirect_count=redirect_count,
            safe_browsing_checked=confirmed_threat is not None,
            virustotal_checked=virustotal_result is not None,
            virustotal_malicious_count=virustotal_malicious_count,
            virustotal_total_engines=virustotal_result.total_engines if virustotal_result else None,
            model_version=settings.model_artifact_path.stem,
        )
    )
    session.commit()

    return CheckResponse(
        url=url,
        verdict=resolved.verdict,
        confidence=resolved.confidence,
        low_confidence=resolved.low_confidence,
        missing_signals=missing_signals,
        typosquat_target=lookalike_of,
        typosquat_real_domain=typosquat_match.real_domain if typosquat_match else None,
        typosquat_diff=typosquat_match.diff_description if typosquat_match else None,
        popularity_rank=rank,
        override_reason=resolved.override_reason,
        reasons=[Reason(feature=name, impact=impact) for name, impact in shown_reasons],
        site_description=site_description,
        reason_narrative=reason_narrative,
        domain_age_days=domain_age_days,
        tls_cert_age_days=tls_cert_age_days,
        dns_resolves=dns_resolves,
        redirect_count=redirect_count,
        safe_browsing_available=safe_browsing_available,
        safe_browsing_checked=confirmed_threat is not None,
        virustotal_available=virustotal_available,
        virustotal_checked=virustotal_result is not None,
        virustotal_malicious_count=virustotal_malicious_count,
        virustotal_total_engines=virustotal_result.total_engines if virustotal_result else None,
        partial=features.partial,
        cached=False,
    )


@router.get("/api/stats", response_model=StatsResponse)
def stats(session: Session = Depends(get_session)) -> StatsResponse:
    counts = dict(
        session.execute(
            select(CheckHistory.verdict, func.count()).group_by(CheckHistory.verdict)
        ).all()
    )
    return StatsResponse(
        safe_count=counts.get("safe", 0),
        phishing_count=counts.get("phishing", 0),
    )
