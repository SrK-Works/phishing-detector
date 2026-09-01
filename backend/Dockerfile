# --- frontend build stage ---
FROM node:20-slim AS frontend-build
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

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
