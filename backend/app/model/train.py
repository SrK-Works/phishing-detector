"""Trains and compares candidate models on the dataset produced by
app.data.build_dataset, ships the best one plus a metadata.json documenting
all candidates' metrics for transparency.

Methodology (the "rigor pass" over the original naive version):

1. **Cross-validated model selection + hyperparameter tuning.** A single
   80/20 split on a ~600-row dataset means the "winner" can just be whoever
   got lucky on 120 rows. Each candidate is instead tuned via GridSearchCV
   over a small hyperparameter grid, scored by mean ROC-AUC across
   `CV_FOLDS` stratified folds of the *training* portion only -- the
   winner is chosen by that cross-validated score, never by peeking at the
   held-out test set.
2. **One honest held-out test set, evaluated once.** The 20% test split is
   never touched during selection or tuning, and -- unlike the original
   version -- the winning model is *not* subsequently refit on 100% of the
   data for shipping. That earlier practice reported metrics for a model
   that was then thrown away, and shipped a different, never-measured
   model instead: the numbers in metadata.json were quietly not a
   description of the artifact actually running in production. Shipping
   exactly the model that was measured costs the last ~20% of a small
   dataset, but the trade-off matters more here than the row count does.
3. **Probability calibration.** A model can rank URLs correctly (good
   ROC-AUC) while its raw predict_proba() is a poorly-calibrated number --
   tree ensembles in particular are notoriously overconfident. Since this
   app's whole UI leans on a shown "N% confidence", `CalibratedClassifierCV`
   (Platt/sigmoid scaling, not isotonic -- isotonic needs more data than
   ~500 rows to avoid overfitting the calibration curve itself) is fit
   alongside the winning pipeline so the shown percentage means what it
   says. Brier score (mean squared error between predicted probability and
   the true outcome) is reported before/after calibration to make that
   improvement concrete rather than assumed.

The shipped artifact bundles *two* related but distinct fitted objects --
see app/model/predict.py's docstring for why.

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
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from app.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

NON_FEATURE_COLUMNS = {"url", "label"}
# label convention (set in app.data.build_dataset): 1 = legitimate, 0 = phishing
LEGIT_LABEL = 1
CV_FOLDS = 5


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
    pipeline: Pipeline  # search.best_estimator_ -- already fit on X_train
    best_params: dict
    cv_roc_auc_mean: float
    cv_roc_auc_std: float
    metrics: dict[str, float]  # uncalibrated test-set metrics


def build_candidates() -> dict[str, tuple[Pipeline, dict]]:
    """Each candidate pairs a pipeline with a hyperparameter grid for
    GridSearchCV. Grids are deliberately small -- this is a ~600-row
    dataset, not a place for an exhaustive search, just enough to avoid
    shipping sklearn's untested bare defaults. `n_jobs=1` on the
    classifiers themselves (parallelism instead comes from GridSearchCV's
    own `n_jobs=-1` across folds/params) avoids nested-parallelism
    thrashing from two layers of joblib trying to fan out at once.
    """
    return {
        "logistic_regression": (
            Pipeline([
                ("impute", SimpleImputer(strategy="median")),
                ("scale", StandardScaler()),
                ("clf", LogisticRegression(max_iter=1000)),
            ]),
            {"clf__C": [0.01, 0.1, 1.0, 10.0]},
        ),
        "random_forest": (
            Pipeline([
                ("impute", SimpleImputer(strategy="median")),
                ("clf", RandomForestClassifier(random_state=0, n_jobs=1)),
            ]),
            {
                "clf__n_estimators": [200, 400],
                "clf__max_depth": [None, 10, 20],
                "clf__min_samples_leaf": [1, 2, 5],
            },
        ),
        "xgboost": (
            Pipeline([
                ("impute", SimpleImputer(strategy="median")),
                ("clf", XGBClassifier(eval_metric="logloss", random_state=0, n_jobs=1)),
            ]),
            {
                "clf__n_estimators": [200, 400],
                "clf__max_depth": [3, 5, 7],
                "clf__learning_rate": [0.05, 0.1, 0.2],
            },
        ),
    }


def evaluate(model, X_test: pd.DataFrame, y_test: pd.Series) -> dict[str, float]:
    """Works on both a plain Pipeline and a fitted CalibratedClassifierCV --
    both expose predict/predict_proba/classes_ identically."""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, list(model.classes_).index(LEGIT_LABEL)]
    return {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, pos_label=LEGIT_LABEL, zero_division=0),
        "recall": recall_score(y_test, y_pred, pos_label=LEGIT_LABEL, zero_division=0),
        "f1": f1_score(y_test, y_pred, pos_label=LEGIT_LABEL, zero_division=0),
        "roc_auc": roc_auc_score(y_test, y_proba),
        # Mean squared error between predicted probability and the true
        # 0/1 outcome -- the standard check for whether a "90% confidence"
        # claim is actually trustworthy, not just whether the final
        # safe/phishing call is right. Lower is better; a constant 50%
        # guess on a balanced dataset scores 0.25.
        "brier_score": brier_score_loss(y_test, y_proba),
    }


def train(dataset_path: Path, artifact_path: Path, metadata_path: Path) -> CandidateResult:
    df = pd.read_parquet(dataset_path)
    if "label" not in df.columns:
        raise ValueError(f"{dataset_path} has no 'label' column")

    X = to_numeric_frame(df)
    y = df["label"].astype(int)
    feature_names = list(X.columns)

    # Held out ONCE, before any model selection or tuning, and never
    # touched again until the single final evaluation below.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=0, stratify=y
    )
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=0)

    results: list[CandidateResult] = []
    for name, (pipeline, param_grid) in build_candidates().items():
        logger.info("Tuning %s over %d cv folds...", name, CV_FOLDS)
        search = GridSearchCV(pipeline, param_grid, scoring="roc_auc", cv=cv, n_jobs=-1)
        search.fit(X_train, y_train)
        std = float(search.cv_results_["std_test_score"][search.best_index_])
        metrics = evaluate(search.best_estimator_, X_test, y_test)
        logger.info(
            "%s: cv_roc_auc=%.4f (+/- %.4f), params=%s, test_metrics=%s",
            name, search.best_score_, std, search.best_params_, metrics,
        )
        results.append(CandidateResult(
            name=name,
            pipeline=search.best_estimator_,
            best_params=search.best_params_,
            cv_roc_auc_mean=search.best_score_,
            cv_roc_auc_std=std,
            metrics=metrics,
        ))

    # Chosen by cross-validated score on the *training* portion only -- not
    # by the held-out test metrics above, which exist purely to report an
    # honest final number for whichever model wins.
    best = max(results, key=lambda r: r.cv_roc_auc_mean)
    logger.info(
        "Best model: %s (cv_roc_auc=%.4f, test_roc_auc=%.4f)",
        best.name, best.cv_roc_auc_mean, best.metrics["roc_auc"],
    )

    calibrated = CalibratedClassifierCV(clone(best.pipeline), method="sigmoid", cv=cv)
    calibrated.fit(X_train, y_train)
    calibrated_metrics = evaluate(calibrated, X_test, y_test)
    logger.info(
        "Calibration effect on held-out test -- brier: %.4f -> %.4f, roc_auc: %.4f -> %.4f",
        best.metrics["brier_score"], calibrated_metrics["brier_score"],
        best.metrics["roc_auc"], calibrated_metrics["roc_auc"],
    )

    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "pipeline": best.pipeline,
            "calibrator": calibrated,
            "feature_names": feature_names,
            "background_sample": X_train.sample(min(100, len(X_train)), random_state=0),
        },
        artifact_path,
    )

    metadata = {
        "model_name": best.name,
        "best_params": best.best_params,
        "cv_folds": CV_FOLDS,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_path": str(dataset_path),
        "dataset_rows": len(df),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "class_balance": {str(k): v for k, v in y.value_counts(normalize=True).items()},
        "all_candidate_metrics": {
            r.name: {
                "cv_roc_auc_mean": r.cv_roc_auc_mean,
                "cv_roc_auc_std": r.cv_roc_auc_std,
                "best_params": r.best_params,
                "test_metrics_uncalibrated": r.metrics,
            }
            for r in results
        },
        "calibrated_test_metrics": calibrated_metrics,
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
