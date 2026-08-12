from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.email_routes import router as email_router
from app.api.phone_routes import router as phone_router
from app.api.routes import router
from app.db.retention import purge_expired_history
from app.db.session import init_db
from app.rate_limit import limiter, rate_limit_exceeded_handler


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    purge_expired_history()
    yield


app = FastAPI(title="Phishing / Fake Website Detector", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.include_router(router)
app.include_router(email_router)
app.include_router(phone_router)

# The built React app (frontend/dist) is copied here at Docker build time so
# the backend can serve everything from a single deployed container -- see
# ../Dockerfile. Locally (frontend/dist absent) the API still works on its
# own; run `npm run dev` in frontend/ for the UI during development instead.
_frontend_dist = Path(__file__).resolve().parent.parent / "static_frontend"
if _frontend_dist.exists():
    app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="frontend")
