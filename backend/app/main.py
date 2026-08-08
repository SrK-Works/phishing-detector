from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Phishing / Fake Website Detector", lifespan=lifespan)
app.include_router(router)

# The built React app (frontend/dist) is copied here at Docker build time so
# the backend can serve everything from a single deployed container -- see
# ../Dockerfile. Locally (frontend/dist absent) the API still works on its
# own; run `npm run dev` in frontend/ for the UI during development instead.
_frontend_dist = Path(__file__).resolve().parent.parent / "static_frontend"
if _frontend_dist.exists():
    app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="frontend")
