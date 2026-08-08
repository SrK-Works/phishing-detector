"""Domain popularity via Tranco's top-1M list: a free, local, always-on
legitimacy signal that doesn't depend on a live network call at request
time (unlike WHOIS/content fetch, which can time out or get blocked by the
site itself). Downloaded once with `python -m app.features.popularity` and
cached to disk; Tranco updates daily, so re-run periodically to stay fresh.

Deliberately NOT fed into the ML model as a training feature: the model's
"legit" training examples are themselves sampled from Tranco
(app/data/build_dataset.py), so "is this domain in Tranco" would be close
to a tautology in training data and the model would over-learn it,
becoming *more* likely to distrust real but lesser-known sites (small
businesses, niche government portals) than before. Instead this is used as
an independent, rule-based override applied on top of the model's own
verdict -- see app/api/routes.py.
"""

from __future__ import annotations

import csv
import io
import zipfile
from pathlib import Path

import requests

from app.config import settings
from app.features.lexical import registered_domain

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

_cache: dict[str, int] | None = None
_cache_path: Path | None = None


def refresh_cache(out_path: Path | None = None) -> int:
    """Downloads the current Tranco top-1M list and writes it to disk as
    plain `rank,domain` rows. Not called from the request path -- run
    manually (or on a schedule) to keep the local cache current."""
    out_path = out_path or settings.tranco_list_path
    resp = requests.get(TRANCO_URL, timeout=60)
    resp.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        name = zf.namelist()[0]
        with zf.open(name) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            rows = [(rank, domain) for rank, domain in reader if domain]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)
    return len(rows)


def _load_ranks(path: Path) -> dict[str, int]:
    global _cache, _cache_path
    if _cache is not None and _cache_path == path:
        return _cache
    ranks: dict[str, int] = {}
    if path.exists():
        with path.open(newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if len(row) < 2:
                    continue
                try:
                    ranks[row[1]] = int(row[0])
                except ValueError:
                    continue
    _cache, _cache_path = ranks, path
    return ranks


def clear_cache() -> None:
    """Drops the in-memory rank cache so the next lookup re-reads from
    disk. Exists mainly for tests that swap `settings.tranco_list_path`."""
    global _cache, _cache_path
    _cache, _cache_path = None, None


def popularity_rank(url: str) -> int | None:
    """1-indexed Tranco rank of the URL's registrable domain, or None if
    it isn't in the cached top-1M list (or the cache hasn't been built)."""
    domain = registered_domain(url)
    if not domain:
        return None
    return _load_ranks(settings.tranco_list_path).get(domain)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    out_path = args.out or settings.tranco_list_path
    n = refresh_cache(args.out)
    print(f"Cached {n} ranked domains to {out_path}")


if __name__ == "__main__":
    main()
