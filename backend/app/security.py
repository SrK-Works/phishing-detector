"""Guards the one place this service does something genuinely risky:
fetching a URL that an anonymous visitor typed in. Without this, the old
project's approach (`urllib.request.urlopen(url)` on raw user input) lets a
visitor make the server issue requests to its own internal network, cloud
metadata endpoints, etc. (SSRF).

Defense used here: resolve the hostname, reject any resolved address that
isn't a public unicast IP, and re-validate on every redirect hop (redirects
are followed manually, not by the HTTP client, specifically so each hop can
be checked). Known residual gap: there's a small TOCTOU window between the
DNS check and the actual TCP connect (DNS rebinding). Closing that fully
requires pinning the checked IP for the actual socket connection (a custom
transport adapter) or fetching through an isolated egress proxy -- worth
doing before this handles untrusted traffic at real scale, but out of scope
for the current milestone.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import requests

ALLOWED_SCHEMES = {"http", "https"}


class SSRFBlockedError(Exception):
    """Raised whenever a URL/redirect target fails the safety check."""


@dataclass(frozen=True)
class FetchResult:
    status_code: int
    final_url: str
    content: bytes
    headers: dict[str, str]
    redirect_count: int


def _is_public_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_all_ips(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"Could not resolve host: {hostname}") from exc
    return sorted({info[4][0] for info in infos})


def assert_host_is_safe(hostname: str) -> None:
    if not hostname:
        raise SSRFBlockedError("Missing host")
    ips = resolve_all_ips(hostname)
    if not ips:
        raise SSRFBlockedError(f"Host resolved to no addresses: {hostname}")
    for ip in ips:
        if not _is_public_ip(ip):
            raise SSRFBlockedError(f"Host {hostname} resolves to non-public address {ip}")


def assert_url_is_safe(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"Unsupported scheme: {parts.scheme!r}")
    if not parts.hostname:
        raise SSRFBlockedError("URL has no host")
    assert_host_is_safe(parts.hostname)


def safe_get(
    url: str,
    *,
    timeout: float,
    max_bytes: int,
    max_redirects: int,
) -> FetchResult:
    """Fetch `url`, following redirects by hand so every hop is re-checked.

    Raises SSRFBlockedError if the URL, or any redirect target, resolves to
    a non-public address, uses a disallowed scheme, or the redirect chain is
    too long. Raises requests exceptions on ordinary network failures.
    """
    current_url = url
    for hop in range(max_redirects + 1):
        assert_url_is_safe(current_url)
        response = requests.get(
            current_url,
            timeout=timeout,
            stream=True,
            allow_redirects=False,
            headers={"User-Agent": "phishing-detector/0.1 (+link-safety-check)"},
        )
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise SSRFBlockedError("Redirect with no Location header")
            current_url = urljoin(current_url, location)
            continue

        content = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            content.extend(chunk)
            if len(content) > max_bytes:
                response.close()
                break
        result = FetchResult(
            status_code=response.status_code,
            final_url=current_url,
            content=bytes(content[:max_bytes]),
            headers=dict(response.headers),
            redirect_count=hop,
        )
        response.close()
        return result

    raise SSRFBlockedError(f"Too many redirects (> {max_redirects}) fetching {url}")
