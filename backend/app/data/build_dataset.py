"""Builds a fresh labeled training dataset, replacing the old project's
frozen 2018 UCI CSV.

Sources (all free, no API key required as of writing):
- Legit / negative examples: Tranco's daily top-1M domain list
  (https://tranco-list.eu), the maintained successor to Alexa rank.
- Phishing / positive examples: PhishTank's verified feed and OpenPhish's
  public feed.

These feed URLs are hardcoded constants controlled by us, not user input,
so they're fetched with a plain `requests` session -- app.security.safe_get
exists specifically to guard *user-submitted* URLs and would be the wrong
tool here (it would reject Tranco's own redirect chain unnecessarily).

Usage:
    python -m app.data.build_dataset --legit-count 1500 --phish-count 1500 \
        --concurrency 40 --out app/data/dataset.parquet
"""

from __future__ import annotations

import argparse
import csv
import io
import logging
import random
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests

from app.features.lexical import _BRAND_DOMAINS
from app.pipeline import extract_all_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"
OPENPHISH_URL = "https://openphish.com/feed.txt"

_HTTP_TIMEOUT = 30

# Real phishing feeds are full URLs -- typically a path/query string from an
# actual attack kit -- while Tranco and hand-built brand URLs are bare
# domains. Without mixing realistic paths into the legit side too, every
# legit training example ends up much shorter than every phishing example,
# and the model learns "long URL -> phishing" as a shortcut that has
# nothing to do with legitimacy: it then misfires on completely ordinary
# real-world URLs like "accounts.google.com/signin". A meaningful fraction
# stays path-less (bare domain visits are common too), the rest get a
# realistic-looking path so the length distributions actually overlap.
_LEGIT_PATH_SAMPLES = [
    "", "", "/", "/login", "/signin", "/account", "/settings",
    "/help", "/about", "/contact", "/support", "/search?q=example+query",
    "/products/12345", "/blog/2024/03/example-article-title",
    "/en-us/docs/getting-started", "/user/profile/settings/security",
    "/checkout/cart?items=3&promo=SAVE10", "/watch?v=dQw4w9WgXcQ",
    "/store/apps/details?id=com.example.app", "/news/world/2024/example-headline",
]


def _with_random_path(url: str) -> str:
    return url + random.choice(_LEGIT_PATH_SAMPLES)


def fetch_tranco_domains(sample_size: int, pool_size: int = 50_000) -> list[str]:
    logger.info("Downloading Tranco top list...")
    resp = requests.get(TRANCO_URL, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        name = zf.namelist()[0]
        with zf.open(name) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            domains = [row[1] for row in reader if len(row) >= 2][:pool_size]
    sample = random.sample(domains, min(sample_size, len(domains)))
    # Real visitors paste/click "www.example.com" (and other subdomains)
    # about as often as the bare apex domain. Tranco only lists apex
    # domains, so without this every legit training example would have
    # subdomain_count == 0 while most phishing URLs naturally have >= 1 --
    # the model would learn "has a subdomain -> phishing" as a shortcut and
    # misfire on ordinary URLs like www.google.com. Mixing in "www." for
    # half the sample breaks that spurious correlation.
    return [f"https://{'www.' + d if random.random() < 0.5 else d}" for d in sample]


def fetch_phishtank_urls(sample_size: int) -> list[str]:
    logger.info("Downloading PhishTank feed...")
    try:
        resp = requests.get(PHISHTANK_URL, timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()
        reader = csv.DictReader(io.StringIO(resp.text))
        urls = [row["url"] for row in reader if row.get("url")]
    except Exception as exc:
        logger.warning("PhishTank fetch failed (%s); continuing without it", exc)
        urls = []
    return random.sample(urls, min(sample_size, len(urls))) if urls else []


def fetch_openphish_urls(sample_size: int) -> list[str]:
    logger.info("Downloading OpenPhish feed...")
    try:
        resp = requests.get(OPENPHISH_URL, timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()
        urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
    except Exception as exc:
        logger.warning("OpenPhish fetch failed (%s); continuing without it", exc)
        urls = []
    return random.sample(urls, min(sample_size, len(urls))) if urls else []


def _extract_row(url: str, label: int) -> dict:
    # Dataset building isn't latency-sensitive like a live user request, so
    # give host/content checks more room than the API's default budget.
    features = extract_all_features(
        url, check_timeout_seconds=8.0, network_timeout_seconds=5.0
    )
    row = features.as_flat_dict()
    row["url"] = url
    row["label"] = label  # 1 = legitimate, 0 = phishing
    return row


def real_brand_urls() -> list[str]:
    """Apex + www URLs for the actual brand domains used by
    app.features.lexical's typosquat-distance check.

    A random Tranco sample almost never lands on one of these specific
    domains, so without forcing them in, the model would never see a
    legit example with brand_typosquat_distance == 0 / is_exact_brand_domain
    == True during training -- only phishing examples that impersonate a
    brand at a small nonzero distance. It would then generalize "close to a
    known brand name" as a phishing signal with no exception carved out for
    the real thing, misflagging the actual brand sites.

    Uses each brand's mapped *real* domain (dict values), not
    f"{brand}.com" -- that assumption is wrong for a growing share of the
    list (e.g. "metamask" -> metamask.io, "hdfc" -> hdfcbank.com), and
    training on the wrong domain would teach the model to recognize a URL
    that isn't actually the real brand site.
    """
    urls = []
    for real_domain in _BRAND_DOMAINS.values():
        urls.append(f"https://{real_domain}")
        urls.append(f"https://www.{real_domain}")
    return urls


def build_dataset(
    legit_count: int, phish_count: int, concurrency: int, out_path: Path
) -> pd.DataFrame:
    brand_urls = real_brand_urls()
    legit_urls = brand_urls + fetch_tranco_domains(max(0, legit_count - len(brand_urls)))
    legit_urls = [_with_random_path(u) for u in legit_urls]

    phish_urls = fetch_phishtank_urls(phish_count // 2)
    phish_urls += fetch_openphish_urls(phish_count - len(phish_urls))
    if not phish_urls:
        raise RuntimeError("Both phishing feeds failed -- cannot build a labeled dataset")

    tasks = [(url, 1) for url in legit_urls] + [(url, 0) for url in phish_urls]
    logger.info(
        "Extracting features for %d URLs (%d legit / %d phishing) at concurrency=%d",
        len(tasks), len(legit_urls), len(phish_urls), concurrency,
    )

    rows = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(_extract_row, url, label): url for url, label in tasks}
        for i, future in enumerate(as_completed(futures), start=1):
            url = futures[future]
            try:
                rows.append(future.result())
            except Exception as exc:
                logger.warning("Skipping %s: %s", url, exc)
            if i % 100 == 0:
                logger.info("Processed %d/%d", i, len(tasks))

    df = pd.DataFrame(rows)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)

    stamped = out_path.with_name(
        f"{out_path.stem}_{datetime.now(timezone.utc):%Y%m%d}{out_path.suffix}"
    )
    df.to_parquet(stamped, index=False)
    logger.info("Wrote %d rows to %s (and %s)", len(df), out_path, stamped)
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legit-count", type=int, default=1500)
    parser.add_argument("--phish-count", type=int, default=1500)
    parser.add_argument("--concurrency", type=int, default=40)
    parser.add_argument(
        "--out", type=Path, default=Path(__file__).parent / "dataset.parquet"
    )
    args = parser.parse_args()
    build_dataset(args.legit_count, args.phish_count, args.concurrency, args.out)


if __name__ == "__main__":
    main()
