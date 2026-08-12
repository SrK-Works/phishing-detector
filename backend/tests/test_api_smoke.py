"""End-to-end smoke test: exercises the real /api/check pipeline (lexical
+ best-effort host/content extraction) against a couple of stable public
URLs. This intentionally makes real network calls -- it is not a unit test
and is slow/flaky-tolerant by design (network features fail soft already).
"""

import phonenumbers
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


def test_check_url_rejects_bare_email_address(client):
    # Live-caught bug: "noreply@email.openai.com" silently became the URL
    # "https://noreply@email.openai.com" (userinfo "noreply", host
    # "email.openai.com"), producing a confusing "domain_unreachable"
    # verdict for what the user actually meant as an email address.
    resp = client.post("/api/check", json={"url": "noreply@email.openai.com"})
    assert resp.status_code == 422
    assert "Email tab" in resp.json()["detail"]


def test_check_url_rejects_non_http_scheme(client):
    resp = client.post("/api/check", json={"url": "ftp://example.com/file.txt"})
    assert resp.status_code == 422
    assert "http/https" in resp.json()["detail"]


def test_check_url_rejects_pseudo_url(client):
    # Live-caught bug: this previously returned 200 with a fabricated-
    # looking "safe, 83% confident" verdict instead of being rejected.
    resp = client.post("/api/check", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 422


def test_check_email_rejects_full_url(client):
    resp = client.post("/api/check-email", json={"email": "https://example.com/login?token=abc"})
    assert resp.status_code == 422
    assert "URL tab" in resp.json()["detail"]


def test_stats_endpoint_returns_counts(client):
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert "safe_count" in body
    assert "phishing_count" in body


def test_stats_endpoint_accepts_type_param(client):
    for check_type in ("url", "email", "phone"):
        resp = client.get("/api/stats", params={"type": check_type})
        assert resp.status_code == 200
        body = resp.json()
        assert "safe_count" in body
        assert "phishing_count" in body


def test_check_email_known_brand_domain(client):
    resp = client.post("/api/check-email", json={"email": "support@paypal.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "safe"
    assert body["override_reason"] == "known_brand_domain"


def test_check_phone_valid_mobile(client):
    mobile = phonenumbers.format_number(
        phonenumbers.example_number_for_type("IN", phonenumbers.PhoneNumberType.MOBILE),
        phonenumbers.PhoneNumberFormat.E164,
    )
    resp = client.post("/api/check-phone", json={"phone": mobile, "region": "IN"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "safe"
    assert body["is_valid"] is True
    assert body["line_type"] == "MOBILE"


def test_check_endpoint_rate_limit_returns_429(client):
    # Exercises the real configured limit (settings.check_rate_limit,
    # "20/minute" by default) against /api/check-phone specifically because
    # it's a fully offline, instant lookup -- no network calls, so sending
    # enough requests to trip the limit doesn't slow the suite down or
    # depend on external services being reachable.
    assert settings.check_rate_limit.endswith("/minute")
    limit = int(settings.check_rate_limit.split("/")[0])

    last_status = None
    for _ in range(limit + 1):
        resp = client.post("/api/check-phone", json={"phone": "9876543210", "region": "IN"})
        last_status = resp.status_code

    assert last_status == 429
    assert "Too many checks" in resp.json()["detail"]
