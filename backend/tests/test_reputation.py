from unittest.mock import Mock, patch

from app.config import settings
from app.features.reputation import check_safe_browsing, check_virustotal


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


def test_virustotal_no_api_key_returns_none_without_calling_network():
    original = settings.virustotal_api_key
    settings.virustotal_api_key = None
    try:
        with patch("app.features.reputation.requests.get") as get:
            assert check_virustotal("https://example.com", timeout=2.0) is None
            get.assert_not_called()
    finally:
        settings.virustotal_api_key = original


def test_virustotal_returns_stats_on_success():
    original = settings.virustotal_api_key
    settings.virustotal_api_key = "fake-key"
    try:
        mock_resp = Mock(status_code=200)
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "harmless": 60,
                        "undetected": 8,
                    }
                }
            }
        }
        with patch("app.features.reputation.requests.get", return_value=mock_resp):
            result = check_virustotal("https://evil.example.com", timeout=2.0)
        assert result.malicious == 5
        assert result.suspicious == 2
        assert result.total_engines == 75
    finally:
        settings.virustotal_api_key = original


def test_virustotal_never_scanned_returns_none():
    original = settings.virustotal_api_key
    settings.virustotal_api_key = "fake-key"
    try:
        mock_resp = Mock(status_code=404)
        with patch("app.features.reputation.requests.get", return_value=mock_resp):
            assert check_virustotal("https://brand-new-site.example", timeout=2.0) is None
    finally:
        settings.virustotal_api_key = original


def test_virustotal_request_failure_returns_none():
    original = settings.virustotal_api_key
    settings.virustotal_api_key = "fake-key"
    try:
        with patch("app.features.reputation.requests.get", side_effect=Exception("boom")):
            assert check_virustotal("https://example.com", timeout=2.0) is None
    finally:
        settings.virustotal_api_key = original
