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
#
# extra_suffixes covers the same failure mode for namespaces the bundled
# PSL snapshot doesn't track at all (not even in its "private" section):
# India's ".bank.in" and ".fin.in" were launched in 2025 by NIXI/RBI
# specifically so different banks/NBFCs each register directly under a
# shared, regulator-verified suffix (e.g. "au.bank.in", "yes.bank.in") --
# the same multi-tenant shape as github.io, just not yet PSL-tracked.
# Without this, EVERY subdomain of bank.in -- including one that doesn't
# even resolve -- was misparsed as the single shared entity "bank.in",
# which is itself a real, popular, Tranco-ranked domain (real banks use
# it) -- so a completely fake "yonosbi.bank.in" inherited that popularity
# and was confidently called "safe". Caught via live testing, not a
# hypothetical: see docs/DATASET.md.
_extract = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
    extra_suffixes=["bank.in", "fin.in"],
)

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

# High-value phishing targets: brands attackers commonly impersonate
# (banking, payments, shipping/delivery, email/social, shopping, crypto,
# e-signature, government services). Deliberately excludes 1-2 char names
# (e.g. "x") -- those sit within edit-distance-2 of huge swaths of
# unrelated real domains. `typosquat_target` below additionally guards
# short brand names with a distance-to-length ratio, a minimum name
# length, and a length-window filter so it doesn't fire on every short
# real domain (see docs/DATASET.md bug #5 -- "ets" vs "etsy" -- for why
# those guards exist).
#
# Maps the short, recognizable slug a typosquatter would actually target
# (what people type/search) to that brand's *real* full domain, used for
# UI display ("the real domain is Y") -- these are deliberately different
# things: e.g. slug "hdfc" (what someone would misspell) vs real domain
# "hdfcbank.com" (what they should actually go to). Getting the real
# domain wrong here would be worse than not knowing it at all, so every
# entry below is either an extremely well-known global brand or was
# verified via web search while building this list (2026-08) rather than
# guessed -- this list is deliberately not exhaustive; growing it further
# should keep that same verify-before-adding discipline rather than
# batch-adding unverified names for the sake of raw count.
_BRAND_DOMAINS: dict[str, str] = {
    # Global tech / social / email
    "google": "google.com", "facebook": "facebook.com", "amazon": "amazon.com",
    "apple": "apple.com", "microsoft": "microsoft.com", "netflix": "netflix.com",
    "instagram": "instagram.com", "whatsapp": "whatsapp.com", "linkedin": "linkedin.com",
    "twitter": "twitter.com", "chatgpt": "chatgpt.com", "openai": "openai.com",
    "dropbox": "dropbox.com", "github": "github.com", "gmail": "gmail.com",
    "outlook": "outlook.com", "icloud": "icloud.com", "yahoo": "yahoo.com",
    "spotify": "spotify.com", "tiktok": "tiktok.com", "snapchat": "snapchat.com",
    "pinterest": "pinterest.com", "reddit": "reddit.com", "adobe": "adobe.com",
    "docusign": "docusign.com",
    # Global banking / payments / crypto
    "paypal": "paypal.com", "bankofamerica": "bankofamerica.com", "chase": "chase.com",
    "wellsfargo": "wellsfargo.com", "citibank": "citibank.com", "hsbc": "hsbc.com",
    "capitalone": "capitalone.com", "usbank": "usbank.com", "venmo": "venmo.com",
    "stripe": "stripe.com", "cashapp": "cashapp.com", "coinbase": "coinbase.com",
    "binance": "binance.com",
    "metamask": "metamask.io",  # not .com -- caught and fixed while building this list
    # Global shopping / shipping
    "ebay": "ebay.com", "usps": "usps.com", "fedex": "fedex.com", "ups": "ups.com",
    "dhl": "dhl.com", "walmart": "walmart.com", "target": "target.com",
    "etsy": "etsy.com", "aliexpress": "aliexpress.com",
    # Global telecom / gaming
    "verizon": "verizon.com", "tmobile": "tmobile.com", "steamcommunity": "steamcommunity.com",

    # Indian banks -- real domains verified via web search (2026-08), not
    # guessed. Several (bankofbaroda, aubank, yesbank) have confirmed live
    # ".bank.in" domains, the new RBI/NIXI-mandated anti-phishing namespace
    # this same fix now correctly recognizes as a suffix (see above).
    "hdfc": "hdfcbank.com", "icici": "icicibank.com", "axis": "axisbank.com",
    "kotak": "kotak.com", "sbi": "sbi.co.in", "pnb": "pnbindia.in",
    "bankofbaroda": "bankofbaroda.in", "unionbank": "unionbankofindia.co.in",
    "bankofindia": "bankofindia.co.in", "federalbank": "federalbank.co.in",
    "aubank": "au.bank.in", "yesbank": "yesbank.in", "idbibank": "idbibank.in",
    "indusind": "indusind.com", "idfcfirst": "idfcfirstbank.com",
    "rblbank": "rblbank.com", "bandhanbank": "bandhanbank.com",
    "canarabank": "canarabank.com",
    # Indian government / public services (very high-value phishing
    # targets: tax refunds, identity documents, rail bookings)
    "incometax": "incometax.gov.in", "uidai": "uidai.gov.in",
    "epfindia": "epfindia.gov.in", "gst": "gst.gov.in",
    "digilocker": "digilocker.gov.in", "irctc": "irctc.co.in",
    "passportindia": "passportindia.gov.in",
    # Indian payments / fintech
    "paytm": "paytm.com", "phonepe": "phonepe.com", "mobikwik": "mobikwik.com",
    "freecharge": "freecharge.in", "bhimupi": "bhimupi.org.in", "npci": "npci.org.in",
    # Indian e-commerce
    "flipkart": "flipkart.com", "myntra": "myntra.com", "snapdeal": "snapdeal.com",
    "meesho": "meesho.com", "bigbasket": "bigbasket.com", "nykaa": "nykaa.com",
    # Indian telecom
    "jio": "jio.com", "airtel": "airtel.in", "myvi": "myvi.in",
}

# Since a brand's slug (the typosquat target, e.g. "hdfc") and its real
# domain's own name (e.g. "hdfcbank") now deliberately differ, the real
# domain itself needs a separate exemption from typosquat matching -- a
# visitor to the actual hdfcbank.com must never be told it looks like a
# lookalike of something else. Computed once at import time, not per
# request.
_REAL_DOMAIN_NAMES = {_extract(f"https://{d}").domain.lower() for d in _BRAND_DOMAINS.values()}

# Below this length, edit-distance matching against a brand name stops being
# a real signal: a short domain has a rapidly rising chance of landing
# within distance 1 of *some* brand purely by coincidence as the brand list
# above grows (e.g. "ets" vs "etsy" -- a real, well-established site, not a
# lookalike). This is a floor on the candidate name itself, independent of
# the distance/length ratio in typosquat_target() below, because the ratio
# alone still let that case through (1/4 == 0.25, exactly at its cutoff).
_MIN_TYPOSQUAT_NAME_LENGTH = 4


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
    name = parts.domain.lower()
    return name in _BRAND_DOMAINS or name in _REAL_DOMAIN_NAMES


def _levenshtein_ops(a: str, b: str) -> list[tuple[str, str, str]]:
    """Minimal edit operations that turn `a` into `b`, via the standard
    Levenshtein DP table's backtrace. Each op is (kind, from_char, to_char)
    where kind is "substitute", "delete" (from_char removed from `a`), or
    "insert" (to_char added, not present in `a`). No position index is
    returned -- domain names are short enough that "the letter X" already
    unambiguously identifies it for the single-edit case this is actually
    used for (typosquat_target only calls this when distance <= 2).
    """
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        dp[i][0] = i
    for j in range(m + 1):
        dp[0][j] = j
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)

    ops: list[tuple[str, str, str]] = []
    i, j = n, m
    while i > 0 or j > 0:
        if i > 0 and j > 0 and a[i - 1] == b[j - 1]:
            i, j = i - 1, j - 1
        elif i > 0 and j > 0 and dp[i][j] == dp[i - 1][j - 1] + 1:
            ops.append(("substitute", a[i - 1], b[j - 1]))
            i, j = i - 1, j - 1
        elif i > 0 and dp[i][j] == dp[i - 1][j] + 1:
            ops.append(("delete", a[i - 1], ""))
            i -= 1
        else:
            ops.append(("insert", "", b[j - 1]))
            j -= 1
    ops.reverse()
    return ops


def describe_typosquat_difference(entered_name: str, brand: str) -> str:
    """Plain-language description of exactly how `entered_name` differs
    from `brand` -- turns "this looks like paypal" into "the letter 'l'
    was swapped for '1'", which is the actionable part of the warning:
    without it, a user overlooking a single swapped letter (the whole
    problem in the first place) has no way to tell what to look for.
    """
    ops = _levenshtein_ops(entered_name, brand)
    if len(ops) == 1:
        kind, frm, to = ops[0]
        if kind == "substitute":
            return f'the letter "{frm}" was swapped for "{to}"'
        if kind == "delete":
            return f'an extra letter "{frm}" was added'
        return f'the letter "{to}" is missing'
    return f"{len(ops)} letters differ from the real domain"


@dataclass(frozen=True)
class TyposquatMatch:
    brand: str
    real_domain: str
    # None for the brand-name-stuffing pattern (e.g.
    # "paypal-secure-login.com") -- there's no single "letter swap" to
    # point to there, the whole matched word is the tell.
    diff_description: str | None


def typosquat_target(url: str) -> TyposquatMatch | None:
    """Which brand this domain looks like a lookalike of, for UI display
    (e.g. "You entered X -- this looks like a lookalike of Y"). Distinct
    from `brand_typosquat_distance` (a raw number the model consumes).
    Catches two distinct patterns, both requiring the domain not be the
    real brand domain itself:

    1. Spelling-close lookalikes ("paypa1.com") -- close in absolute edit
       distance AND close relative to the name's length, so a short real
       domain like "app.com" doesn't get flagged just for sharing a short
       prefix with "apple". Candidates are also filtered to brands within
       2 characters of the entered name's length before any distance is
       computed at all: a name can't be a spelling-close lookalike of a
       brand of wildly different length, so this both keeps matching fast
       as the brand list grows and further shrinks false-positive risk
       (fewer, more plausible candidates considered per name).
    2. Brand-name stuffing ("paypal-secure-login.com") -- a known brand
       name appearing as a whole hyphen/underscore-separated word
       alongside other words. This used to be caught only loosely, if at
       all, by a blanket "has a hyphen in the domain" feature -- which
       produces far more false positives today than it used to (hyphens
       are common in ordinary product names now) than true positives, so
       it was dropped in favor of this more precise, brand-specific check.
       Whole-word matching (not a raw substring check) matters here: it
       avoids flagging something like "target-market.com" for containing
       "target" *inside* an unrelated compound... except when "target"
       itself is the whole word, which is exactly the risk with brand
       names that are also common English words -- a known, accepted
       trade-off, same as with any short/common brand name in this list.
    """
    parts = _extract(url)
    name = parts.domain.lower()
    if not name or name in _BRAND_DOMAINS or name in _REAL_DOMAIN_NAMES:
        return None

    words = re.split(r"[-_]", name)
    if len(words) > 1:
        for brand in _BRAND_DOMAINS:
            if brand in words:
                return TyposquatMatch(
                    brand=brand, real_domain=_BRAND_DOMAINS[brand], diff_description=None
                )

    if len(name) < _MIN_TYPOSQUAT_NAME_LENGTH:
        return None

    candidates = [b for b in _BRAND_DOMAINS if abs(len(b) - len(name)) <= 2]
    if not candidates:
        return None
    brand, distance = min(
        ((b, _levenshtein(name, b)) for b in candidates), key=lambda kv: kv[1]
    )
    if distance == 0:
        return None
    longest = max(len(name), len(brand))
    if distance <= 2 and distance / longest <= 0.25:
        return TyposquatMatch(
            brand=brand,
            real_domain=_BRAND_DOMAINS[brand],
            diff_description=describe_typosquat_difference(name, brand),
        )
    return None


@dataclass(frozen=True)
class LexicalFeatures:
    url_length: int
    has_ip_address: bool
    uses_url_shortener: bool
    has_at_symbol: bool
    has_double_slash_redirect: bool
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
        subdomain_count=subdomain_count(url),
        uses_https=uses_https(url),
        digit_ratio_in_domain=digit_ratio_in_domain(url),
        domain_entropy=domain_entropy(url),
        has_suspicious_tld=has_suspicious_tld(url),
        brand_typosquat_distance=brand_typosquat_distance(url),
        is_exact_brand_domain=is_exact_brand_domain(url),
    )
