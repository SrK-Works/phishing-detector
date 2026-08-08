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
from app.features.lexical import typosquat_target
from app.features.popularity import popularity_rank
from app.features.reputation import check_safe_browsing
from app.model.predict import PhishingModel
from app.pipeline import extract_all_features
from app.verdict import resolve_verdict

# Override reasons that replace the model's own verdict outright -- SHAP
# reasons for the raw ML call would contradict the shown verdict in these
# cases, so they're suppressed. "no_track_record" only softens confidence
# on an unchanged verdict, so its SHAP reasons stay relevant and shown.
VERDICT_CHANGING_OVERRIDES = {"confirmed_threat", "typosquat_lookalike", "popular_domain"}

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
    popularity_rank: int | None
    override_reason: str | None
    reasons: list[Reason]
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

    lookalike_of = typosquat_target(url)
    rank = popularity_rank(url)
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
            popularity_rank=rank,
            override_reason=cached_row.override_reason,
            reasons=[],
            partial=False,
            cached=True,
        )

    # Run the full feature pipeline and the Safe Browsing check concurrently
    # -- they're independent, and Safe Browsing is a single fixed-endpoint
    # HTTPS call so there's no reason to add its latency on top serially.
    # Both are internally self-timeout-bounded, so .result() below can't hang.
    executor = ThreadPoolExecutor(max_workers=2)
    try:
        features_future = executor.submit(extract_all_features, url)
        threat_future = executor.submit(
            check_safe_browsing, url, settings.network_timeout_seconds
        )
        features = features_future.result()
        confirmed_threat = threat_future.result()
    finally:
        executor.shutdown(wait=False)

    model = get_model()
    prediction = model.predict(features.as_flat_dict())
    resolved = resolve_verdict(
        prediction,
        popularity_rank=rank,
        confirmed_threat=confirmed_threat,
        typosquat_target=lookalike_of,
        whois_missing=features.whois_missing,
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
        popularity_rank=rank,
        override_reason=resolved.override_reason,
        reasons=(
            []
            if resolved.override_reason in VERDICT_CHANGING_OVERRIDES
            else [Reason(feature=name, impact=impact) for name, impact in prediction.top_reasons]
        ),
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
