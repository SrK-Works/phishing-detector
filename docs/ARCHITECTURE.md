# Architecture

## Request flow (`POST /api/check`)

1. `app/api/routes.py` normalizes the URL (adds `https://` if no scheme) and
   checks `check_history` for a result within `PHISH_CACHE_TTL_HOURS` (24h
   default), keyed by SHA-256 of the URL (`app/db/models.py::url_hash`).
2. On a cache miss, `app/pipeline.py::extract_all_features` runs:
   - **Lexical** (`app/features/lexical.py`) — always, instant, no network:
     URL length, IP-literal host, shortener domains, `@`/`//` tricks,
     hyphenated domains, subdomain depth, HTTPS scheme, digit ratio,
     domain-string entropy, suspicious TLDs, and Levenshtein distance to a
     short list of high-value brand names (typosquat signal).
   - **Host** (`app/features/host.py`) and **Content**
     (`app/features/content.py`) — run concurrently in a thread pool, each
     independently timeout-bounded, under one overall
     `PHISH_CHECK_TIMEOUT_SECONDS` budget (6s default) so a slow WHOIS
     server can't also stall the content fetch or blow the whole request
     past a reasonable response time. Missing/timed-out values become
     `None`, imputed at training/inference time — see below. A companion
     `host_whois_missing` boolean is set explicitly so the model can tell
     "we don't know" apart from an imputed guess.
3. `app/model/predict.py::PhishingModel` turns the flattened feature dict
   into a verdict, a confidence score, and the top SHAP-ranked features that
   drove it. If the probability lands within 0.15 of the 0.5 boundary,
   `low_confidence=True` is set — this is shown in the UI as "Uncertain"
   rather than a confidently-colored badge.
4. `app/verdict.py::resolve_verdict` applies independent, rule-based
   overrides on top of the model's statistical call, highest authority
   first — see below.
5. The result is written to `check_history` and returned.

## Verdict overrides (`app/verdict.py`)

The ML model alone was found to misfire in two recurring, structural ways
that more training data can reduce but not eliminate: (a) it has no way to
express real ground truth, only probabilities, and (b) a 600-row synthetic
dataset can't cover every rare combination (e.g. a domain that's both
decades-old *and* one edit away from a known brand). Rather than trying to
make the model itself unshakeable, three independent, purpose-built checks
sit on top of it and can override its call, in priority order:

1. **Google Safe Browsing** (`app/features/reputation.py`) — a confirmed
   hit against Google's threat list is ground truth, not a guess, so it
   wins outright. Optional: gated on a self-service, free
   `PHISH_SAFE_BROWSING_API_KEY`; the app runs fully without it, just with
   this one layer off. Only ever queries Google's own fixed endpoint with
   the URL as a parameter — never fetches the URL itself, so it sits
   outside `security.py`'s SSRF guard by construction.
2. **Typosquat lookalike** (`app/features/lexical.py::typosquat_target`) —
   a close-but-not-exact edit distance to a curated list of ~50 commonly
   impersonated brands, gated by a distance-to-length *ratio* (not just a
   raw edit distance) so short real domains like `app.com` don't get
   flagged just for sharing a prefix with `apple`. Deliberately not a
   model *training* feature at all: it's precise enough on its own to
   drive the verdict directly, and doing it as a rule means it can't be
   drowned out by other features the way `brand_typosquat_distance` was
   when it was just one signal among many (a real domain, `paypa1.com`,
   scored 95.7% "safe" from the model alone).
3. **Popularity** (`app/features/popularity.py`) — a domain ranked in
   Tranco's top ~200k is treated as established enough to override a
   shaky/borderline model call. Also deliberately kept out of *training*:
   the model's own "legit" training examples are themselves sampled from
   Tranco, so feeding rank in as a training feature would be close to
   circular and would likely make the model trust lesser-known-but-real
   sites *less*, not more.
4. Otherwise, the model's own verdict/confidence stands as-is, including
   the "uncertain" framing when the underlying signal is genuinely thin.

## Why content fetching goes through `app/security.py`

`content.py` is the one place the server fetches a URL a visitor typed in.
`security.safe_get` resolves the hostname and rejects private/loopback/
link-local/reserved/multicast addresses *before* connecting, and re-checks
on every redirect hop (redirects are followed by hand, not by the HTTP
client, specifically so each hop gets checked). This is the fix for the SSRF
shape of bug in the original project, which called
`urllib.request.urlopen(url)` directly on user input.

Known residual gap: there's a small TOCTOU window between the DNS check and
the actual connect (DNS rebinding). Fully closing it means pinning the
checked IP for the real socket connection. Worth doing before this ever
handles real untrusted traffic at scale; out of scope for the current
milestone and called out here so it isn't forgotten.

## Data & training (offline, not part of the request path)

- `app/data/build_dataset.py` pulls legit domains from Tranco's daily top-1M
  list and phishing URLs from PhishTank + OpenPhish's free feeds, runs the
  same `extract_all_features` pipeline over each (with a larger timeout
  budget than live requests get, since this isn't latency-sensitive), and
  writes a labeled, dated parquet snapshot.
- `app/model/train.py` coerces the mixed bool/int/float/`None` feature
  columns to numeric (`None` → `NaN`), trains Logistic Regression / Random
  Forest / XGBoost behind a `SimpleImputer`, picks the best by ROC-AUC on a
  held-out split, refits it on the full dataset, and ships it via `joblib`
  alongside `metadata.json` (all candidates' metrics, feature list, training
  date) for transparency.

## Deployment

Single Docker image (`backend/Dockerfile`): a Node build stage compiles the
React frontend, then it's copied into the Python image and served by
FastAPI's `StaticFiles` mount (`app/main.py`) alongside the API — one
process, one deploy target, no CORS to configure. Built from the repo root:
`docker compose up --build`.

Two data files are required at runtime but not committed to the repo (see
`.gitignore`) — they need to exist in the image/volume before first request:
`app/model/artifacts/model.joblib` (`python -m app.model.train`) and
`app/data/tranco.csv` (`python -m app.features.popularity`). Both are plain
downloads/builds, not secrets, so they can be baked into the image at build
time. `PHISH_SAFE_BROWSING_API_KEY` *is* a secret if set — pass it as a
runtime environment variable, never bake it into the image.
