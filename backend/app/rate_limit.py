"""Per-IP rate limiting via slowapi, applied to the check endpoints (they
make outbound calls to rate-limited/quota'd third-party APIs, and the URL
checker fetches arbitrary user-submitted URLs -- both are abuse vectors
without a limit). Kept as its own module so app.main and each router module
can share one Limiter instance without import cycles.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    # Matches this app's existing error-body convention ({"detail": ...}),
    # which frontend/src/lib/api.ts already reads for any non-2xx response
    # -- no frontend changes needed to surface this message.
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many checks -- please wait a moment and try again."},
    )
