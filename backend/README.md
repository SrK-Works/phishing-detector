# Backend

FastAPI service: feature extraction, model training, and the `/api/check` /
`/api/stats` API.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows
pip install -e ".[dev]"
```

## Run the API (development)

```bash
uvicorn app.main:app --reload
```

## Tests

```bash
pytest                             # unit tests + SSRF guard tests run offline
pytest tests/test_api_smoke.py     # end-to-end, needs a trained model + network
```

## Train the model

`app/data/dataset.parquet` is committed to the repo -- it's the frozen,
already-built training set, so this step never touches the network:

```bash
python -m app.model.train --dataset app/data/dataset.parquet
```

Trains/compares Logistic Regression, Random Forest, and XGBoost, saving the
best one to `app/model/artifacts/model.joblib` (gitignored -- too large to
commit, and fully reproducible from the committed dataset) with
`metadata.json` documenting how it was chosen. The API loads that artifact
lazily on first `/api/check` call. The Docker build runs this same step
automatically, so `docker compose up --build` needs no manual training step.

## Refresh the dataset (optional, needs network)

Only needed if you want newer threat data than what's committed. Pulls
legit domains from Tranco's top-1M list and phishing URLs from
[Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (an
hourly-updated aggregator, no API key needed -- PhishTank's own feed now
rate-limits without a registered key, and OpenPhish's free feed has been
throttled to near-nothing):

```bash
python -m app.data.build_dataset --legit-count 3000 --phish-count 3000 --concurrency 40
python -m app.model.train --dataset app/data/dataset.parquet
```

This overwrites the committed `dataset.parquet` -- commit the result if you
want the refreshed data to stick. Extracting features for thousands of URLs
does live DNS/TLS/host checks per URL and can take 15-30+ minutes; the
build checkpoints its output every 250 rows so an interruption doesn't lose
the whole run.
