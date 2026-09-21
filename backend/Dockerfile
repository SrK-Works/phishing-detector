# --- frontend build stage ---
# Matches the Node version CI/local dev actually test against (see
# .github/workflows/ci.yml) -- kept in sync deliberately, not left to whatever
# a floating "-slim" tag happens to resolve to.
FROM node:24-slim AS frontend-build
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# --- backend runtime stage ---
FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml ./pyproject.toml
COPY backend/app ./app
RUN pip install --no-cache-dir .

# Pre-built React app, served by FastAPI's StaticFiles mount (see app/main.py).
COPY --from=frontend-build /frontend/dist ./static_frontend

# app/data/dataset.parquet is committed (see .gitignore) specifically so this
# step never touches the network or an external feed at build/deploy time --
# training is fast (CPU-only, a few minutes) and fully reproducible from that
# one file. See backend/README.md if you want to refresh the dataset itself.
RUN python -m app.model.train --dataset app/data/dataset.parquet

# Drop root before serving requests. /data is the SQLite volume mount point
# (see docker-compose.yml) -- pre-creating and chowning it here means the
# named volume inherits appuser ownership on first creation, since Docker
# copies a mount point's existing content/ownership into a fresh volume.
RUN useradd --create-home --uid 1000 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /app /data
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
