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
    external = sum(1 for a in anchors if _link_domain(base_domain, a["href"], page_url) not in ("", base_domain))
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
    external = sum(1 for src in tags if _link_domain(base_domain, src, page_url) not in ("", base_domain))
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
