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
     `PHISH_CHECK_TIMEOUT_SECONDS` budget (4s default) so a slow WHOIS
     server can't also stall the content fetch or blow the whole request
     past a reasonable response time. Missing/timed-out values become
     `None`, imputed at training/inference time — see below.
3. `app/model/predict.py::PhishingModel` turns the flattened feature dict
   into a verdict, a confidence score, and the top SHAP-ranked features that
   drove it.
4. The result is written to `check_history` and returned.

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
