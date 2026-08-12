"""Host-level features: DNS, WHOIS, TLS certificate. These make network
calls, so every function is timeout-bounded and fails soft (returns None /
False rather than raising) since a slow or unresponsive registrar/DNS
server is common and shouldn't take the whole check down.
"""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from urllib.parse import urlsplit

import whois

from app.security import SSRFBlockedError, assert_host_is_safe


def _run_with_timeout(fn, timeout: float):
    """Run fn() in a worker thread, bounded by `timeout`.

    Deliberately does NOT use ThreadPoolExecutor as a context manager: its
    __exit__ calls shutdown(wait=True), which blocks until the submitted
    work finishes regardless of the timeout below (Python threads can't be
    force-killed) -- that would silently defeat the whole point of this
    helper for a hung WHOIS/socket call. shutdown(wait=False) lets the
    caller move on immediately; the worker thread is left to finish (or
    stay blocked) on its own.
    """
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(fn)
        try:
            return future.result(timeout=timeout)
        except (FutureTimeoutError, Exception):
            return None
    finally:
        executor.shutdown(wait=False)


def _first(value):
    return value[0] if isinstance(value, list) and value else value


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _safe_hostname(url: str) -> str | None:
    """`urlsplit(url).hostname`, but never raises. A malformed netloc (e.g.
    an IPv4 address wrapped in brackets, which is only valid syntax for
    IPv6) makes `urlsplit` itself raise `ValueError` -- caught live via a
    pasted "user@[192.168.1.1]"-shaped email address, which crashed the
    whole request with a 500 before this existed. Treated the same as "no
    hostname at all" (None), consistent with every caller's existing
    `if not hostname: return None/False` handling.
    """
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


@dataclass(frozen=True)
class WhoisInfo:
    creation_date: datetime | None
    expiration_date: datetime | None


def dns_resolves(url: str) -> bool:
    hostname = _safe_hostname(url)
    if not hostname:
        return False
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except (socket.gaierror, UnicodeError):
        # UnicodeError: socket.getaddrinfo IDNA-encodes the hostname before
        # resolving, and IDNA has its own constraints (each label <=63
        # octets, never empty) -- a hostname violating those raises
        # UnicodeError, not socket.gaierror. Caught live via an
        # artificially long email domain label, which crashed the whole
        # request with a 500 before this was caught here too. A hostname
        # that can't even be encoded for DNS obviously "doesn't resolve".
        return False


def lookup_whois(url: str, timeout: float) -> WhoisInfo | None:
    hostname = _safe_hostname(url)
    if not hostname:
        return None

    record = _run_with_timeout(lambda: whois.whois(hostname), timeout)
    if not record:
        return None
    creation = _first(record.creation_date) if hasattr(record, "creation_date") else None
    expiration = _first(record.expiration_date) if hasattr(record, "expiration_date") else None
    if not isinstance(creation, datetime):
        creation = None
    if not isinstance(expiration, datetime):
        expiration = None
    return WhoisInfo(creation_date=creation, expiration_date=expiration)


def domain_age_days(whois_info: WhoisInfo | None) -> int | None:
    if whois_info is None or whois_info.creation_date is None:
        return None
    return (datetime.now(timezone.utc) - _as_utc(whois_info.creation_date)).days


def registration_length_days(whois_info: WhoisInfo | None) -> int | None:
    if whois_info is None or not whois_info.creation_date or not whois_info.expiration_date:
        return None
    return (_as_utc(whois_info.expiration_date) - _as_utc(whois_info.creation_date)).days


def tls_cert_age_days(url: str, timeout: float) -> int | None:
    hostname = _safe_hostname(url)
    if not hostname:
        return None
    try:
        assert_host_is_safe(hostname)
    except SSRFBlockedError:
        return None

    def _fetch_cert():
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()

    cert = _run_with_timeout(_fetch_cert, timeout)
    not_before = cert.get("notBefore") if cert else None
    if not not_before:
        return None
    try:
        issued = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - issued).days


def has_valid_https(url: str, timeout: float) -> bool:
    return tls_cert_age_days(url, timeout) is not None


@dataclass(frozen=True)
class HostFeatures:
    dns_resolves: bool
    domain_age_days: int | None
    registration_length_days: int | None
    has_valid_https: bool
    tls_cert_age_days: int | None

    def as_dict(self) -> dict[str, float | int | bool | None]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


def extract_host_features(url: str, timeout: float) -> HostFeatures:
    resolves = dns_resolves(url)
    if not resolves:
        return HostFeatures(
            dns_resolves=False,
            domain_age_days=None,
            registration_length_days=None,
            has_valid_https=False,
            tls_cert_age_days=None,
        )

    # WHOIS and the TLS handshake are independent network calls; running
    # them sequentially would let this function's worst case run to ~2x
    # `timeout` instead of ~1x, which matters because the caller
    # (app.pipeline) budgets host extraction as a single bounded step
    # alongside content extraction.
    with ThreadPoolExecutor(max_workers=2) as pool:
        whois_future = pool.submit(lookup_whois, url, timeout)
        cert_future = pool.submit(tls_cert_age_days, url, timeout)
        whois_info = whois_future.result()
        cert_age = cert_future.result()

    return HostFeatures(
        dns_resolves=resolves,
        domain_age_days=domain_age_days(whois_info),
        registration_length_days=registration_length_days(whois_info),
        has_valid_https=cert_age is not None,
        tls_cert_age_days=cert_age,
    )
