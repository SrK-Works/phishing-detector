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

# Model artifact + Tranco snapshot are built separately (see backend/README.md)
# and expected to be baked in or mounted at deploy time, not generated here.
COPY backend/app/model/artifacts ./app/model/artifacts

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
