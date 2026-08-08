"""Trains and compares candidate models on the dataset produced by
app.data.build_dataset, ships the best one (by ROC-AUC on a held-out split)
plus a metadata.json documenting all candidates' metrics for transparency.

Usage:
    python -m app.model.train --dataset app/data/dataset.parquet
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from app.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

NON_FEATURE_COLUMNS = {"url", "label"}
# label convention (set in app.data.build_dataset): 1 = legitimate, 0 = phishing
LEGIT_LABEL = 1


def to_numeric_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Coerces the mixed bool/int/float/None feature columns produced by
    app.pipeline.ExtractedFeatures.as_flat_dict() into a plain numeric frame
    with NaN for missing values, ready for a SimpleImputer."""
    numeric = df.drop(columns=[c for c in NON_FEATURE_COLUMNS if c in df.columns]).copy()
    for col in numeric.columns:
        if numeric[col].dtype == bool:
            numeric[col] = numeric[col].astype(float)
        else:
            numeric[col] = pd.to_numeric(numeric[col], errors="coerce")
    return numeric


@dataclass
class CandidateResult:
    name: str
    pipeline: Pipeline
    metrics: dict[str, float]


def build_candidates() -> dict[str, Pipeline]:
    return {
        "logistic_regression": Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000)),
        ]),
        "random_forest": Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("clf", RandomForestClassifier(n_estimators=300, random_state=0, n_jobs=-1)),
        ]),
        "xgboost": Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("clf", XGBClassifier(
                n_estimators=300,
                max_depth=5,
                learning_rate=0.1,
                eval_metric="logloss",
                random_state=0,
                n_jobs=-1,
            )),
        ]),
    }


def evaluate(pipeline: Pipeline, X_test: pd.DataFrame, y_test: pd.Series) -> dict[str, float]:
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, list(pipeline.classes_).index(LEGIT_LABEL)]
    return {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, pos_label=LEGIT_LABEL, zero_division=0),
        "recall": recall_score(y_test, y_pred, pos_label=LEGIT_LABEL, zero_division=0),
        "f1": f1_score(y_test, y_pred, pos_label=LEGIT_LABEL, zero_division=0),
        "roc_auc": roc_auc_score(y_test, y_proba),
    }


def train(dataset_path: Path, artifact_path: Path, metadata_path: Path) -> CandidateResult:
    df = pd.read_parquet(dataset_path)
    if "label" not in df.columns:
        raise ValueError(f"{dataset_path} has no 'label' column")

    X = to_numeric_frame(df)
    y = df["label"].astype(int)
    feature_names = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=0, stratify=y
    )

    results: list[CandidateResult] = []
    for name, pipeline in build_candidates().items():
        logger.info("Training %s...", name)
        pipeline.fit(X_train, y_train)
        metrics = evaluate(pipeline, X_test, y_test)
        logger.info("%s metrics: %s", name, metrics)
        results.append(CandidateResult(name=name, pipeline=pipeline, metrics=metrics))

    best = max(results, key=lambda r: r.metrics["roc_auc"])
    logger.info("Best model: %s (roc_auc=%.4f)", best.name, best.metrics["roc_auc"])

    # Report metrics come from the untouched holdout split above. Refit the
    # winning pipeline on the full dataset for the artifact we actually ship.
    final_pipeline = build_candidates()[best.name]
    final_pipeline.fit(X, y)

    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "pipeline": final_pipeline,
            "feature_names": feature_names,
            "background_sample": X_train.sample(min(100, len(X_train)), random_state=0),
        },
        artifact_path,
    )

    metadata = {
        "model_name": best.name,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_path": str(dataset_path),
        "dataset_rows": len(df),
        "class_balance": {str(k): v for k, v in y.value_counts(normalize=True).items()},
        "all_candidate_metrics": {r.name: r.metrics for r in results},
        "feature_names": feature_names,
    }
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2))
    logger.info("Saved model to %s and metadata to %s", artifact_path, metadata_path)
    return best


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset", type=Path, default=Path(__file__).parent.parent / "data" / "dataset.parquet"
    )
    parser.add_argument("--artifact", type=Path, default=settings.model_artifact_path)
    parser.add_argument("--metadata", type=Path, default=settings.model_metadata_path)
    args = parser.parse_args()
    train(args.dataset, args.artifact, args.metadata)


if __name__ == "__main__":
    main()
