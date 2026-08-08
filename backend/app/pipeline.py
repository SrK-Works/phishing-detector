"""Orchestrates the three feature tiers under one overall time budget:

- lexical: instant, always runs, no network.
- host + content: both make network calls, so they run concurrently rather
  than back-to-back, and are each allowed to fail/timeout independently --
  a slow WHOIS server shouldn't also block the content fetch, and neither
  should keep the API response waiting past `check_timeout_seconds`.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass

from app.config import settings
from app.features.content import ContentFeatures, extract_content_features
from app.features.host import HostFeatures, extract_host_features
from app.features.lexical import LexicalFeatures, extract_lexical_features


@dataclass(frozen=True)
class ExtractedFeatures:
    url: str
    lexical: LexicalFeatures
    host: HostFeatures | None
    content: ContentFeatures | None
    partial: bool  # True if host and/or content didn't finish in time

    def as_flat_dict(self) -> dict[str, float | int | bool | None]:
        flat: dict[str, float | int | bool | None] = {}
        flat.update({f"lexical_{k}": v for k, v in self.lexical.as_dict().items()})
        if self.host is not None:
            flat.update({f"host_{k}": v for k, v in self.host.as_dict().items()})
        if self.content is not None:
            flat.update({f"content_{k}": v for k, v in self.content.as_dict().items()})
        return flat


def extract_all_features(
    url: str,
    *,
    check_timeout_seconds: float | None = None,
    network_timeout_seconds: float | None = None,
) -> ExtractedFeatures:
    lexical = extract_lexical_features(url)

    remaining_budget = check_timeout_seconds or settings.check_timeout_seconds
    network_timeout = min(
        network_timeout_seconds or settings.network_timeout_seconds, remaining_budget
    )

    host_result: HostFeatures | None = None
    content_result: ContentFeatures | None = None
    partial = False

    # See app.features.host._run_with_timeout for why this isn't a `with` block.
    executor = ThreadPoolExecutor(max_workers=2)
    try:
        host_future = executor.submit(extract_host_features, url, network_timeout)
        content_future = executor.submit(
            extract_content_features,
            url,
            timeout=network_timeout,
            max_bytes=settings.max_content_bytes,
            max_redirects=settings.max_redirects,
        )
        # Wait on both concurrently, sharing the same deadline. Waiting on
        # host_future first (for up to the full budget) before even checking
        # content_future would starve content of any time left over whenever
        # host happened to be slow -- and host/content latency isn't random
        # noise here: a dead phishing domain fails DNS/connect almost
        # instantly, while a live legit domain takes real time to fetch, so
        # sequential waiting would have systematically starved content
        # extraction on legit URLs and baked a class-correlated artifact
        # into the training data.
        done, _ = wait([host_future, content_future], timeout=remaining_budget)

        if host_future in done:
            try:
                host_result = host_future.result()
            except Exception:
                partial = True
        else:
            partial = True

        if content_future in done:
            try:
                content_result = content_future.result()
            except Exception:
                partial = True
        else:
            partial = True
    finally:
        executor.shutdown(wait=False)

    return ExtractedFeatures(
        url=url,
        lexical=lexical,
        host=host_result,
        content=content_result,
        partial=partial,
    )
