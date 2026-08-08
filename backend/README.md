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

## Build a dataset and train a model

```bash
python -m app.data.build_dataset --legit-count 1500 --phish-count 1500 --concurrency 40
python -m app.model.train --dataset app/data/dataset.parquet
```

This downloads fresh URLs from Tranco (legit) and PhishTank/OpenPhish
(phishing), extracts all features for each, and trains/compares Logistic
Regression, Random Forest, and XGBoost, saving the best one to
`app/model/artifacts/model.joblib` with `metadata.json` documenting how it
was chosen. The API loads that artifact lazily on first `/api/check` call.
