from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import CheckHistory, url_hash
from app.db.session import get_session
from app.model.predict import PhishingModel
from app.pipeline import extract_all_features

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
            reasons=[],
            partial=False,
            cached=True,
        )

    features = extract_all_features(url)
    model = get_model()
    prediction = model.predict(features.as_flat_dict())

    session.add(
        CheckHistory(
            url_hash=digest,
            url=url,
            verdict=prediction.verdict,
            confidence=prediction.confidence,
            model_version=settings.model_artifact_path.stem,
        )
    )
    session.commit()

    return CheckResponse(
        url=url,
        verdict=prediction.verdict,
        confidence=prediction.confidence,
        reasons=[Reason(feature=name, impact=impact) for name, impact in prediction.top_reasons],
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
