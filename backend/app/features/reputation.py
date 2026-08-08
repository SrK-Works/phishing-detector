"""Google Safe Browsing v4 lookup: the only ground-truth signal in this
app (everything else is a statistical guess or a heuristic). Optional --
gated on a user-supplied API key -- so the app runs fully self-contained
without it, just with this one extra layer of protection turned off.

Get a free key at:
  1. https://console.cloud.google.com/projectcreate (any project name)
  2. https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
     -> Enable
  3. https://console.cloud.google.com/apis/credentials -> Create credentials
     -> API key
Then set PHISH_SAFE_BROWSING_API_KEY in backend/.env. Free tier covers far
more lookups per day than a personal demo will ever use.
"""

from __future__ import annotations

import requests

from app.config import settings

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

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
