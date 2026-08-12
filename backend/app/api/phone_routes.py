from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import PhoneCheckHistory, url_hash
from app.db.session import get_session
from app.phone_checks import check_phone_number
from app.rate_limit import limiter

SCORER_VERSION = "phone-v1"

router = APIRouter()


class PhoneCheckRequest(BaseModel):
    phone: str = Field(min_length=1, max_length=32)
    region: str = "IN"


class PhoneCheckResponse(BaseModel):
    e164: str | None
    region_code: str | None
    is_valid: bool
    is_possible: bool
    line_type: str | None
    carrier_name: str | None
    verdict: str
    confidence: float
    low_confidence: bool
    override_reason: str | None


@router.post("/api/check-phone", response_model=PhoneCheckResponse)
@limiter.limit(settings.check_rate_limit)
def check_phone(
    request: Request, payload: PhoneCheckRequest, session: Session = Depends(get_session)
) -> PhoneCheckResponse:
    # No cache-read path: phonenumbers is an instant offline lookup, so
    # there's nothing expensive to save latency on. Always compute fresh
    # and do one unconditional insert, purely for the stats footer/history.
    result = check_phone_number(payload.phone, default_region=payload.region)

    session.add(
        PhoneCheckHistory(
            number_hash=url_hash(result.e164 or payload.phone),
            e164=result.e164,
            region_code=result.region_code,
            is_valid=result.is_valid,
            is_possible=result.is_possible,
            line_type=result.line_type,
            carrier_name=result.carrier_name,
            verdict=result.verdict,
            confidence=result.confidence,
            low_confidence=result.low_confidence,
            override_reason=result.override_reason,
            scorer_version=SCORER_VERSION,
        )
    )
    session.commit()

    return PhoneCheckResponse(
        e164=result.e164,
        region_code=result.region_code,
        is_valid=result.is_valid,
        is_possible=result.is_possible,
        line_type=result.line_type,
        carrier_name=result.carrier_name,
        verdict=result.verdict,
        confidence=result.confidence,
        low_confidence=result.low_confidence,
        override_reason=result.override_reason,
    )
