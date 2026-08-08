# Phishing / Fake Website Detector

A URL safety checker: paste a URL, get a verdict (legitimate vs. phishing) with a
confidence score and a plain-language explanation of *why*.

This is a from-scratch modern rebuild of a 2022 B.Tech final-year project. The
original used a 2018 static dataset and several since-dead data sources (Alexa
rank, unauthenticated Google search scraping). This rewrite:

- Pulls fresh phishing URLs from PhishTank/OpenPhish and legit/popular domains
  from the Tranco list, instead of a frozen CSV.
- Splits URL features into instant lexical checks (no network) and slower
  host/content checks (WHOIS, DNS, TLS, page content), with a bounded time
  budget per request.
- Ships model predictions with a SHAP-based explanation instead of a bare
  safe/unsafe label.
- Guards the content-fetch step against SSRF (no fetching of internal/private
  network addresses on the server's behalf).

Status: work in progress rebuild. See `docs/ARCHITECTURE.md` and
`docs/DATASET.md` for details as they're filled in.

## Layout

- `backend/` — FastAPI app: feature extraction, model training/inference, API.
- `frontend/` — Vite + React + TypeScript single-page UI.

## Development

See `backend/README.md` (once added) for setup instructions.
