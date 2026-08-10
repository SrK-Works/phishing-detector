"""Page-content features. The only place this codebase touches a
user-submitted URL's actual body -- always via app.security.safe_get, never
a raw urlopen/requests.get, so every fetch (and every redirect hop) is
SSRF-checked first.
"""

from __future__ import annotations

from dataclasses import dataclass
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
    # Raw page metadata, kept for the AI-generated site-description feature
    # only. Deliberately excluded from as_dict() below: that method feeds
    # app.pipeline's flat feature dict, which build_dataset.py writes
    # straight to the training parquet, and free text would poison the ML
    # feature set (coerced to an all-NaN column at training time). Text like
    # this belongs nowhere near model training anyway -- it's page-supplied
    # and untrusted, unlike our extracted numeric/boolean signals.
    page_title: str | None = None
    meta_description: str | None = None

    def as_dict(self) -> dict[str, float | int | bool | None]:
        return {
            "fetch_succeeded": self.fetch_succeeded,
            "redirect_count": self.redirect_count,
            "external_anchor_ratio": self.external_anchor_ratio,
            "has_iframe": self.has_iframe,
            "has_mailto_form": self.has_mailto_form,
            "external_resource_ratio": self.external_resource_ratio,
        }


_EMPTY = ContentFeatures(
    fetch_succeeded=False,
    redirect_count=0,
    external_anchor_ratio=None,
    has_iframe=None,
    has_mailto_form=None,
    external_resource_ratio=None,
    page_title=None,
    meta_description=None,
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


def _page_title(soup: BeautifulSoup) -> str | None:
    tag = soup.find("title")
    if tag and tag.string and tag.string.strip():
        return tag.string.strip()[:200]
    return None


def _meta_description(soup: BeautifulSoup) -> str | None:
    tag = soup.find("meta", attrs={"name": "description"})
    content = tag.get("content") if tag else None
    if content and content.strip():
        return content.strip()[:300]
    return None


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
            page_title=None,
            meta_description=None,
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
        page_title=_page_title(soup),
        meta_description=_meta_description(soup),
    )
