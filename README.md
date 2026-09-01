# Phishing / Fake Website Detector

A phishing/scam detector for URLs, emails, and phone numbers: paste one in,
get a verdict (legitimate vs. phishing) with a confidence score and a
plain-language explanation of *why*.

This is a from-scratch modern rebuild of a 2022 B.Tech final-year project. The
original used a 2018 static dataset and several since-dead data sources (Alexa
rank, unauthenticated Google search scraping). This rewrite:

- Trains on a real, current dataset (Tranco for legit domains, a live
  phishing-feed aggregator for phishing URLs) instead of a frozen 2018 CSV --
  see `docs/DATASET.md`.
- Splits URL features into instant lexical checks (no network) and slower
  host/content checks (WHOIS, DNS, TLS, page content), with a bounded time
  budget per request.
- Ships model predictions with a SHAP-based explanation instead of a bare
  safe/unsafe label.
- Guards the content-fetch step against SSRF (no fetching of internal/private
  network addresses on the server's behalf).

Status: functional and hardened for public use (rate limiting, SSRF guards,
retention/purge of stored history), CI on every push (backend + frontend
tests), and a 6,000-row training dataset. See `docs/TESTING.md` for the
honest remaining gaps (e.g. no automated E2E/Playwright suite) and
`docs/ARCHITECTURE.md` / `docs/DATASET.md` for design details.

## Layout

- `backend/` — FastAPI app: feature extraction, model training/inference, API.
- `frontend/` — Vite + React + TypeScript single-page UI.

## Development

See `backend/README.md` for backend setup, running the API, tests, and
dataset/model training instructions. For the frontend, `cd frontend && npm
install && npm run dev`.

To run the whole app in one container (built frontend served by the
backend): `docker compose up --build`.

## License

MIT — see `LICENSE`.
