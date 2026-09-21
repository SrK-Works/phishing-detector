"""Integration tests for app.pipeline.extract_all_features -- the one place
lexical + host + content extraction actually run together. Host/content
themselves are unit-tested in isolation (test_host.py, test_content.py);
this file is specifically about the combination logic app/pipeline.py
docstring describes: running host+content concurrently under one shared
deadline, and letting each fail/time out independently without blocking
the other or the overall response. Previously only exercised indirectly
by test_api_smoke.py's one well-behaved google.com case.
"""

import time
from unittest.mock import patch

from app.features.content import ContentFeatures
from app.features.host import HostFeatures
from app.pipeline import extract_all_features

URL = "https://example.com/"


def _host(domain_age_days=100):
    return HostFeatures(
        dns_resolves=True,
        domain_age_days=domain_age_days,
        registration_length_days=365,
        has_valid_https=True,
        tls_cert_age_days=30,
    )


def _content(fetch_succeeded=True):
    return ContentFeatures(
        fetch_succeeded=fetch_succeeded,
        redirect_count=0,
        external_anchor_ratio=0.1,
        has_iframe=False,
        has_mailto_form=False,
        external_resource_ratio=0.1,
    )


def test_both_host_and_content_succeed():
    with (
        patch("app.pipeline.extract_host_features", return_value=_host()),
        patch("app.pipeline.extract_content_features", return_value=_content()),
    ):
        result = extract_all_features(URL, check_timeout_seconds=2.0, network_timeout_seconds=2.0)

    assert result.partial is False
    assert result.whois_missing is False
    assert result.content_unavailable is False
    flat = result.as_flat_dict()
    assert flat["host_domain_age_days"] == 100
    assert flat["content_fetch_succeeded"] is True
    assert flat["host_whois_missing"] is False


def test_host_timeout_does_not_block_content_result():
    def slow_host(url, timeout):
        time.sleep(2.0)
        return _host()

    with (
        patch("app.pipeline.extract_host_features", side_effect=slow_host),
        patch("app.pipeline.extract_content_features", return_value=_content()),
    ):
        result = extract_all_features(URL, check_timeout_seconds=0.2, network_timeout_seconds=0.2)

    assert result.partial is True
    assert result.host is None
    assert result.whois_missing is True
    # content wasn't the slow one -- it should still have completed and
    # come back, proving host's timeout didn't starve content of its share
    # of the shared deadline.
    assert result.content is not None
    assert result.content_unavailable is False


def test_content_exception_does_not_block_host_result():
    def failing_content(url, timeout, max_bytes, max_redirects):
        raise ConnectionError("simulated fetch failure")

    with (
        patch("app.pipeline.extract_host_features", return_value=_host()),
        patch("app.pipeline.extract_content_features", side_effect=failing_content),
    ):
        result = extract_all_features(URL, check_timeout_seconds=2.0, network_timeout_seconds=2.0)

    assert result.partial is True
    assert result.content is None
    assert result.content_unavailable is True
    # host wasn't the one that failed -- it should still be populated.
    assert result.host is not None
    assert result.whois_missing is False


def test_host_succeeds_but_whois_lookup_itself_failed():
    # domain_age_days=None means DNS resolved but WHOIS specifically came
    # back empty -- whois_missing must still be True even though `host`
    # itself is not None, per ExtractedFeatures.whois_missing's docstring.
    with (
        patch("app.pipeline.extract_host_features", return_value=_host(domain_age_days=None)),
        patch("app.pipeline.extract_content_features", return_value=_content()),
    ):
        result = extract_all_features(URL, check_timeout_seconds=2.0, network_timeout_seconds=2.0)

    assert result.partial is False
    assert result.host is not None
    assert result.whois_missing is True
