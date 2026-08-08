"""Pure, offline URL features: no network calls, safe to run on any input.

Every function takes a URL string and returns a float/bool/int. They are
deliberately side-effect free so they can be unit tested without mocking
anything, and so the API can return a preliminary verdict instantly before
the slower host/content checks (see app.features.host / app.features.content)
resolve.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, fields
from urllib.parse import urlsplit

import tldextract

# Bundled public-suffix-list snapshot only; never fetch over the network.
# include_psl_private_domains=True matters here: without it, tldextract only
# recognizes official ICANN TLDs, so multi-tenant hosting platforms in the
# PSL's "private" section (github.io, blogspot.com, netlify.app, s3
# buckets, ...) get misparsed as if the platform name itself were the
# registrable domain (e.g. "evil-user.github.io" -> domain="github"). That
# both breaks the typosquat/brand check (falsely "matching" the platform's
# own name) and misses the real signal: phishing kits are commonly hosted
# on exactly these free platforms, where the subdomain is the attacker's.
_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV4_HEX_RE = re.compile(r"^(0x[0-9a-fA-F]{1,2}\.){3}0x[0-9a-fA-F]{1,2}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")

_SHORTENER_DOMAINS = {
    "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co",
    "tinyurl.com", "tr.im", "is.gd", "cli.gs", "tiny.cc", "url4.eu",
    "su.pr", "snipurl.com", "short.to", "buff.ly", "rebrand.ly", "cutt.ly",
    "bit.do", "lnkd.in", "db.tt", "qr.ae", "adf.ly", "po.st", "v.gd",
}

_SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "tk", "ml", "ga", "cf", "work",
    "click", "link", "loan", "download", "review", "country", "kim",
}

# A small, deliberately short list of high-value phishing targets. Extend
# with care -- a long list increases false positives on unrelated domains
# that happen to share a short common substring.
_BRAND_DOMAINS = [
    "google", "facebook", "amazon", "apple", "microsoft", "paypal",
    "netflix", "instagram", "whatsapp", "linkedin", "twitter", "chatgpt",
    "openai", "bankofamerica", "chase", "wellsfargo", "dropbox", "github",
    "gmail", "outlook", "icloud", "yahoo", "ebay", "steamcommunity",
]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def registered_domain(url: str) -> str:
    """e.g. https://accounts.login.paypal.com/x -> 'paypal.com'"""
    parts = _extract(url)
    if not parts.domain:
        return ""
    return f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain


def has_ip_address(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    return bool(
        _IPV4_RE.match(host) or _IPV4_HEX_RE.match(host) or (":" in host and _IPV6_RE.match(host))
    )


def url_length(url: str) -> int:
    return len(url)


def uses_url_shortener(url: str) -> bool:
    parts = _extract(url)
    domain = f"{parts.domain}.{parts.suffix}".lower()
    return domain in _SHORTENER_DOMAINS


def has_at_symbol(url: str) -> bool:
    return "@" in url


def has_double_slash_redirect(url: str) -> bool:
    """'//' appearing anywhere after the scheme separator is a classic
    open-redirect / hidden-destination trick."""
    scheme_sep = url.find("://")
    start = scheme_sep + 3 if scheme_sep != -1 else 0
    return "//" in url[start:]


def has_hyphen_in_domain(url: str) -> bool:
    parts = _extract(url)
    return "-" in parts.domain


def subdomain_count(url: str) -> int:
    parts = _extract(url)
    if not parts.subdomain:
        return 0
    return parts.subdomain.count(".") + 1


def uses_https(url: str) -> bool:
    return urlsplit(url).scheme.lower() == "https"


def digit_ratio_in_domain(url: str) -> float:
    parts = _extract(url)
    domain = parts.domain
    if not domain:
        return 0.0
    digits = sum(ch.isdigit() for ch in domain)
    return digits / len(domain)


def domain_entropy(url: str) -> float:
    parts = _extract(url)
    return _shannon_entropy(parts.domain)


def has_suspicious_tld(url: str) -> bool:
    parts = _extract(url)
    return parts.suffix.lower() in _SUSPICIOUS_TLDS


def brand_typosquat_distance(url: str) -> int:
    """Minimum edit distance from the registrable domain's name to any
    known brand name. A small nonzero distance (e.g. 1-2) on a domain that
    is NOT the real brand domain is a strong phishing signal; 0 means it
    either *is* the brand or shares its exact name (further disambiguated
    by the caller using the full registered domain, not just this number).
    """
    parts = _extract(url)
    name = parts.domain.lower()
    if not name:
        return -1
    return min(_levenshtein(name, brand) for brand in _BRAND_DOMAINS)


def is_exact_brand_domain(url: str) -> bool:
    parts = _extract(url)
    return parts.domain.lower() in _BRAND_DOMAINS


@dataclass(frozen=True)
class LexicalFeatures:
    url_length: int
    has_ip_address: bool
    uses_url_shortener: bool
    has_at_symbol: bool
    has_double_slash_redirect: bool
    has_hyphen_in_domain: bool
    subdomain_count: int
    uses_https: bool
    digit_ratio_in_domain: float
    domain_entropy: float
    has_suspicious_tld: bool
    brand_typosquat_distance: int
    is_exact_brand_domain: bool

    def as_dict(self) -> dict[str, float | int | bool]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


def extract_lexical_features(url: str) -> LexicalFeatures:
    return LexicalFeatures(
        url_length=url_length(url),
        has_ip_address=has_ip_address(url),
        uses_url_shortener=uses_url_shortener(url),
        has_at_symbol=has_at_symbol(url),
        has_double_slash_redirect=has_double_slash_redirect(url),
        has_hyphen_in_domain=has_hyphen_in_domain(url),
        subdomain_count=subdomain_count(url),
        uses_https=uses_https(url),
        digit_ratio_in_domain=digit_ratio_in_domain(url),
        domain_entropy=domain_entropy(url),
        has_suspicious_tld=has_suspicious_tld(url),
        brand_typosquat_distance=brand_typosquat_distance(url),
        is_exact_brand_domain=is_exact_brand_domain(url),
    )
