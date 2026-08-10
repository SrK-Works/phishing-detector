"""Ground-truth reputation lookups -- the only non-statistical signals in
this app (everything else is a model guess or a heuristic). Both are
optional, gated on a user-supplied API key, so the app runs fully
self-contained without them, just with that one extra layer of protection
turned off.

Google Safe Browsing v4:
  1. https://console.cloud.google.com/projectcreate (any project name)
  2. https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
     -> Enable
  3. https://console.cloud.google.com/apis/credentials -> Create credentials
     -> API key
Then set PHISH_SAFE_BROWSING_API_KEY in backend/.env. Free tier covers far
more lookups per day than a personal demo will ever use.

VirusTotal v3 (a second, independent source -- a 70+-engine consensus
rather than a single vendor's blocklist):
  1. Create a free account at https://www.virustotal.com
  2. Copy your API key from https://www.virustotal.com/gui/my-apikey
Then set PHISH_VIRUSTOTAL_API_KEY in backend/.env. Free tier is heavily
rate-limited (4 requests/minute, 500/day) -- fine for personal use.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import requests

from app.config import settings

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VIRUSTOTAL_URL_TEMPLATE = "https://www.virustotal.com/api/v3/urls/{url_id}"

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def check_safe_browsing(url: str, timeout: float) -> bool | None:
    """True if Safe Browsing has this URL flagged, False if checked and
    clean, None if the check itself couldn't be performed (no API key
    configured, or the request failed/timed out) -- callers must treat
    None as "unknown", never as "clean".

    This calls Google's API with the URL as a parameter; it never fetches
    the URL itself, so app.security's SSRF guard doesn't apply here --
    the only outbound connection is to Google's fixed, trusted endpoint.
    """
    if not settings.safe_browsing_api_key:
        return None

    body = {
        "client": {"clientId": "phishing-detector-rebuild", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(
            SAFE_BROWSING_URL,
            params={"key": settings.safe_browsing_api_key},
            json=body,
            timeout=timeout,
        )
        resp.raise_for_status()
        return bool(resp.json().get("matches"))
    except Exception:
        return None


@dataclass(frozen=True)
class VirusTotalResult:
    malicious: int
    suspicious: int
    total_engines: int


def check_virustotal(url: str, timeout: float) -> VirusTotalResult | None:
    """None if no API key configured, the request fails/times out, or
    VirusTotal simply has no prior scan on file for this exact URL (a 404,
    common for brand-new or rare URLs) -- callers must treat all of those
    as "no data", never as "clean". This is a pure lookup, not a scan
    request: submitting a URL for a fresh scan and polling for results can
    take well over a minute, which would blow this app's real-time check
    budget, so an unscanned URL is simply reported as unknown rather than
    triggering a submit-and-wait flow.

    This calls VirusTotal's API with the URL as a parameter; it never
    fetches the URL itself, so app.security's SSRF guard doesn't apply
    here -- the only outbound connection is to VirusTotal's fixed, trusted
    endpoint.
    """
    if not settings.virustotal_api_key:
        return None

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        resp = requests.get(
            VIRUSTOTAL_URL_TEMPLATE.format(url_id=url_id),
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=timeout,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    except Exception:
        return None

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = malicious + suspicious + stats.get("harmless", 0) + stats.get("undetected", 0)
    return VirusTotalResult(malicious=malicious, suspicious=suspicious, total_engines=total)
