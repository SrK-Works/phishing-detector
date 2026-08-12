from unittest.mock import Mock, patch

import dns.exception
import dns.resolver

from app.features.email_checks import (
    extract_domain,
    has_dmarc_record,
    has_mx_records,
    has_spf_record,
)


def test_extract_domain_from_bare_domain():
    assert extract_domain("example.com") == "example.com"


def test_extract_domain_from_full_address():
    assert extract_domain("user@example.com") == "example.com"


def test_extract_domain_normalizes_case_and_whitespace():
    assert extract_domain("  User@Example.COM  ") == "example.com"


def test_extract_domain_splits_on_last_at_only():
    # technically valid (if unusual) to have "@" in the local part
    assert extract_domain('"a@b"@example.com') == "example.com"


def test_extract_domain_keeps_subdomain():
    assert extract_domain("user@mail.example.com") == "mail.example.com"


def test_has_mx_records_true_when_records_present():
    fake_answer = [Mock()]
    with patch("dns.resolver.resolve", return_value=fake_answer):
        assert has_mx_records("example.com", timeout=2.0) is True


def test_has_mx_records_false_on_nxdomain():
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        assert has_mx_records("nonexistent.invalid", timeout=2.0) is False


def test_has_mx_records_false_on_no_answer():
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()):
        assert has_mx_records("example.com", timeout=2.0) is False


def test_has_mx_records_none_on_timeout():
    with patch("dns.resolver.resolve", side_effect=dns.exception.Timeout()):
        assert has_mx_records("example.com", timeout=2.0) is None


def _txt_answer(*values: str):
    records = []
    for value in values:
        rdata = Mock()
        rdata.strings = [value.encode("utf-8")]
        records.append(rdata)
    return records


def test_has_spf_record_true_when_present():
    with patch("dns.resolver.resolve", return_value=_txt_answer("v=spf1 include:_spf.google.com ~all")):
        assert has_spf_record("example.com", timeout=2.0) is True


def test_has_spf_record_false_when_txt_present_but_not_spf():
    with patch("dns.resolver.resolve", return_value=_txt_answer("google-site-verification=abc123")):
        assert has_spf_record("example.com", timeout=2.0) is False


def test_has_spf_record_false_on_no_records():
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()):
        assert has_spf_record("example.com", timeout=2.0) is False


def test_has_spf_record_none_on_lookup_failure():
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoNameservers()):
        assert has_spf_record("example.com", timeout=2.0) is None


def test_has_dmarc_record_queries_underscore_dmarc_subdomain():
    with patch("dns.resolver.resolve", return_value=_txt_answer("v=DMARC1; p=reject")) as mock_resolve:
        assert has_dmarc_record("example.com", timeout=2.0) is True
        mock_resolve.assert_called_once_with("_dmarc.example.com", "TXT", lifetime=2.0)


def test_has_dmarc_record_false_when_absent():
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        assert has_dmarc_record("example.com", timeout=2.0) is False
