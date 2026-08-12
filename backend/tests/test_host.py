"""Pure/fast regression tests for host.py's malformed-input handling. Both
cases here fail during local parsing/encoding (before any real network
call), so they run instantly with no mocking needed -- unlike the rest of
host.py's WHOIS/DNS/TLS logic, which isn't unit-tested directly anywhere in
this codebase (see the module docstring's own "fails soft" claim, which
these two cases falsified until now).
"""

from app.features.host import _safe_hostname, dns_resolves, lookup_whois, tls_cert_age_days

# An IPv4 address in brackets is invalid syntax (brackets are IPv6-only) --
# urlsplit() itself raises ValueError for this, before any hostname is even
# extracted. Caught live via a pasted "user@[192.168.1.1]"-shaped email
# address, which crashed the whole /api/check-email request with a 500.
_BRACKETED_IPV4_URL = "https://[192.168.1.1]"

# A single DNS label over 63 octets is invalid -- socket.getaddrinfo's
# internal IDNA encoding raises UnicodeError for this, before any actual
# network call happens. Caught live via a pasted email address with an
# artificially long domain label, same crash-to-500 outcome.
_OVERLONG_LABEL_URL = "https://" + "b" * 240 + ".com"


def test_safe_hostname_returns_none_for_bracketed_ipv4():
    assert _safe_hostname(_BRACKETED_IPV4_URL) is None


def test_safe_hostname_returns_hostname_for_normal_url():
    assert _safe_hostname("https://example.com/path") == "example.com"


def test_dns_resolves_does_not_crash_on_bracketed_ipv4():
    assert dns_resolves(_BRACKETED_IPV4_URL) is False


def test_dns_resolves_does_not_crash_on_overlong_label():
    assert dns_resolves(_OVERLONG_LABEL_URL) is False


def test_lookup_whois_does_not_crash_on_bracketed_ipv4():
    assert lookup_whois(_BRACKETED_IPV4_URL, timeout=2.0) is None


def test_tls_cert_age_days_does_not_crash_on_bracketed_ipv4():
    assert tls_cert_age_days(_BRACKETED_IPV4_URL, timeout=2.0) is None
