"""End-to-end smoke test: exercises the real /api/check pipeline (lexical
+ best-effort host/content extraction) against a couple of stable public
URLs. This intentionally makes real network calls -- it is not a unit test
and is slow/flaky-tolerant by design (network features fail soft already).
"""

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

pytestmark = pytest.mark.skipif(
    not settings.model_artifact_path.exists(),
    reason="no trained model artifact yet -- run app.data.build_dataset then app.model.train first",
)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_check_known_legit_domain(client):
    resp = client.post("/api/check", json={"url": "https://www.google.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] in ("safe", "phishing")
    assert 0.0 <= body["confidence"] <= 1.0


def test_check_rejects_empty_url(client):
    resp = client.post("/api/check", json={"url": "   "})
    assert resp.status_code == 422


def test_stats_endpoint_returns_counts(client):
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert "safe_count" in body
    assert "phishing_count" in body
