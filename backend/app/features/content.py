"""Page-content features. The only place this codebase touches a
user-submitted URL's actual body -- always via app.security.safe_get, never
a raw urlopen/requests.get, so every fetch (and every redirect hop) is
SSRF-checked first.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from app.features.lexical import registered_domain
from app.security import FetchResult, safe_get

# Domains whose presence in a page's links/scripts doesn't indicate
# anything about the *page's* legitimacy, so counting them as "external"
# just adds noise to these ratios: generic multi-tenant CDNs/libraries used
# by countless unrelated sites (Google Fonts, Cloudflare, jsDelivr, ...),
# plus major platforms' own separate asset domains (Google's gstatic.com,
# Wikipedia's wikimedia.org, ...) -- normal infrastructure, not "linking
# off-site". Without this, a page that legitimately spreads static assets
# across a sibling domain it also owns scores identically to a phishing
# page pulling scripts from a genuinely unrelated attacker domain -- this
# is what caused accounts.google.com and en.wikipedia.org to read as
# suspicious purely from asset hosting, independent of any actual content.
_KNOWN_INFRA_DOMAINS = {
    "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
    "cloudflare.com", "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com",
    "bootstrapcdn.com", "fontawesome.com", "cloudfront.net", "akamaihd.net",
    "fastly.net", "gravatar.com", "polyfill.io",
    "wikimedia.org", "fbcdn.net", "twimg.com", "ytimg.com", "ssl-images-amazon.com",
}


def _is_external(base_domain: str, link_domain: str) -> bool:
    return link_domain not in ("", base_domain) and link_domain not in _KNOWN_INFRA_DOMAINS


@dataclass(frozen=True)
class ContentFeatures:
    fetch_succeeded: bool
    redirect_count: int
    external_anchor_ratio: float | None
    has_iframe: bool | None
    has_mailto_form: bool | None
    external_resource_ratio: float | None

    def as_dict(self) -> dict[str, float | int | bool | None]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


_EMPTY = ContentFeatures(
    fetch_succeeded=False,
    redirect_count=0,
    external_anchor_ratio=None,
    has_iframe=None,
    has_mailto_form=None,
    external_resource_ratio=None,
)


def _link_domain(base_domain: str, href: str, page_url: str) -> str:
    absolute = urljoin(page_url, href)
    return registered_domain(absolute)


def _external_anchor_ratio(soup: BeautifulSoup, base_domain: str, page_url: str) -> float:
    anchors = [a for a in soup.find_all("a", href=True) if not a["href"].startswith("#")]
    if not anchors:
        return 0.0
    external = sum(
        1 for a in anchors if _is_external(base_domain, _link_domain(base_domain, a["href"], page_url))
    )
    return external / len(anchors)


def _has_iframe(soup: BeautifulSoup) -> bool:
    return len(soup.find_all("iframe")) > 0


def _has_mailto_form(soup: BeautifulSoup) -> bool:
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        if "mailto:" in action.lower():
            return True
    return False


def _external_resource_ratio(soup: BeautifulSoup, base_domain: str, page_url: str) -> float:
    tags = []
    for tag_name, attr in (("script", "src"), ("link", "href")):
        for tag in soup.find_all(tag_name):
            if tag.get(attr):
                tags.append((tag[attr]))
    if not tags:
        return 0.0
    external = sum(1 for src in tags if _is_external(base_domain, _link_domain(base_domain, src, page_url)))
    return external / len(tags)


def extract_content_features(
    url: str,
    *,
    timeout: float,
    max_bytes: int,
    max_redirects: int,
) -> ContentFeatures:
    try:
        result: FetchResult = safe_get(
            url, timeout=timeout, max_bytes=max_bytes, max_redirects=max_redirects
        )
    except Exception:
        return _EMPTY

    if result.status_code >= 400:
        return ContentFeatures(
            fetch_succeeded=False,
            redirect_count=result.redirect_count,
            external_anchor_ratio=None,
            has_iframe=None,
            has_mailto_form=None,
            external_resource_ratio=None,
        )

    base_domain = registered_domain(result.final_url)
    soup = BeautifulSoup(result.content, "lxml")
    return ContentFeatures(
        fetch_succeeded=True,
        redirect_count=result.redirect_count,
        external_anchor_ratio=_external_anchor_ratio(soup, base_domain, result.final_url),
        has_iframe=_has_iframe(soup),
        has_mailto_form=_has_mailto_form(soup),
        external_resource_ratio=_external_resource_ratio(soup, base_domain, result.final_url),
    )
