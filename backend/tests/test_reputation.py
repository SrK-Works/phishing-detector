from unittest.mock import Mock, patch

from app.config import settings
from app.features.reputation import check_safe_browsing


def test_no_api_key_returns_none_without_calling_network():
    original = settings.safe_browsing_api_key
    settings.safe_browsing_api_key = None
    try:
        with patch("app.features.reputation.requests.post") as post:
            assert check_safe_browsing("https://example.com", timeout=2.0) is None
            post.assert_not_called()
    finally:
        settings.safe_browsing_api_key = original


def test_match_returns_true():
    original = settings.safe_browsing_api_key
    settings.safe_browsing_api_key = "fake-key"
    try:
        mock_resp = Mock()
        mock_resp.json.return_value = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
        mock_resp.raise_for_status.return_value = None
        with patch("app.features.reputation.requests.post", return_value=mock_resp):
            assert check_safe_browsing("https://evil.example.com", timeout=2.0) is True
    finally:
        settings.safe_browsing_api_key = original


def test_no_match_returns_false():
    original = settings.safe_browsing_api_key
    settings.safe_browsing_api_key = "fake-key"
    try:
        mock_resp = Mock()
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status.return_value = None
        with patch("app.features.reputation.requests.post", return_value=mock_resp):
            assert check_safe_browsing("https://example.com", timeout=2.0) is False
    finally:
        settings.safe_browsing_api_key = original


def test_request_failure_returns_none():
    original = settings.safe_browsing_api_key
    settings.safe_browsing_api_key = "fake-key"
    try:
        with patch("app.features.reputation.requests.post", side_effect=Exception("boom")):
            assert check_safe_browsing("https://example.com", timeout=2.0) is None
    finally:
        settings.safe_browsing_api_key = original
